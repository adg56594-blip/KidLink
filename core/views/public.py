import json

from django.conf import settings
from django.core.cache import cache
from django.contrib import messages
from django.db import IntegrityError, transaction
from django.db.models import Max
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_GET, require_POST

from .. import crypto
from ..forms import ChildForm
from ..models import Event, Registration, RegistrationLink, ScanLog
from ..qr import build_fragment, verify_fragment
from ..utils import client_ip, rate_limited

SW_REVISION = "2"
SW_ASSETS = [
    "css/app.css", "js/app.js", "js/scan.js", "js/scanner.js", "vendor/jsQR.js",
    "fonts/jakarta.woff2", "fonts/jakarta-ext.woff2", "fonts/nunito.woff2", "fonts/nunito-ext.woff2", "fonts/nunito-italic.woff2",
    "img/seme2026-emblem.webp", "img/icon-192.png",
]
FAMILY_FIELDS = ["parent_name", "parent_phone", "parent_phone2", "paroisse", "charge_name", "charge_phone"]


@require_GET
def home(request):
    events = list(Event.featured()[:3])
    return render(request, "public/home.html", {"events": events, "featured": events[0] if events else None})


@require_GET
def scanner(request):
    return render(request, "public/scanner.html", {"public_url": settings.KIDLINK_PUBLIC_URL})


@require_GET
def scan_shell(request, public_id=None):
    """Page affichée après le scan. Elle ne contient AUCUNE donnée : tout est lu dans
    le fragment du QR et vérifié dans le téléphone (fonctionne hors ligne)."""
    return render(request, "public/scan.html", {"public_key": crypto.public_key_spki_b64()})


@csrf_exempt  # point d'accès public, sans session ni effet sur un compte ; protégé par limitation de débit
@require_POST
def api_verify(request):
    ip = client_ip(request)
    if rate_limited(f"verify:{ip}", 60, 60):
        return JsonResponse({"status": "rate_limited"}, status=429)
    try:
        body = json.loads(request.body.decode("utf-8")[:4096])
        public_id = str(body.get("id", ""))[:12]
        fragment = str(body.get("f", ""))[:2048]
    except (ValueError, UnicodeDecodeError, AttributeError):
        return JsonResponse({"status": "bad_request"}, status=400)

    decoded = verify_fragment(public_id, fragment)
    reg = Registration.objects.select_related("event").filter(public_id=public_id).first()
    if not decoded.ok:
        status = ScanLog.FORGED
    elif reg is None:
        status = ScanLog.EXPIRED  # signature authentique mais données effacées après l'événement
    elif reg.qr_fragment != fragment:
        # Signature authentique mais contenu différent de la fiche actuelle : c'est un ancien
        # bracelet dont la fiche a été corrigée (le serveur est le seul à pouvoir signer).
        status = ScanLog.REPLACED
    elif reg.revoked_at:
        status = ScanLog.REVOKED
    elif reg.event.retention_over:
        status = ScanLog.EXPIRED
    else:
        status = ScanLog.VALID
    ScanLog.objects.create(registration=reg if status != ScanLog.FORGED else None, result=status, ip_hash=crypto.anonymize_ip(ip))
    out = {"status": status, "checked_at": timezone.localtime().strftime("%d/%m/%Y à %H:%M")}
    if status == ScanLog.VALID:
        out["event"] = reg.event.title
        # Les anciens bracelets (QR version 1) ne contiennent pas le nom du chargé : le serveur le
        # complète, uniquement pour qui présente le bracelet authentique et à jour.
        if reg.charge_name and not (decoded.data or {}).get("charge_name"):
            out["charge_name"] = reg.charge_name
    return JsonResponse(out)


# ------------------------------------------------------------------ lien d'inscription
def _get_link(request, token):
    """Seules les tentatives avec un lien INVALIDE sont comptées : un chargé qui inscrit
    50 enfants n'est jamais bloqué, mais deviner un lien est impossible (192 bits + blocage)."""
    ip = client_ip(request)
    bad_key = f"linkbad:{ip}"
    if cache.get("rl-block:" + bad_key):
        raise Http404
    link = RegistrationLink.objects.select_related("event").filter(token_hash=crypto.token_hash(token)).first()
    if link is None:
        if rate_limited(bad_key, 30, 600):
            cache.set("rl-block:" + bad_key, 1, 900)
        raise Http404
    return link


@require_http_methods(["GET", "POST"])
def link_form(request, token):
    link = _get_link(request, token)
    event = link.event
    session_key = f"fam_{link.pk}"
    names = [r.full_name for r in link.registrations.all()]
    ctx = {"link": link, "event": event, "names": names}

    if not link.is_usable:
        return render(request, "public/link_closed.html", ctx, status=410 if link.is_full else 403)

    if request.method == "POST":
        if rate_limited(f"linkpost:{client_ip(request)}", 300, 600):
            messages.error(request, "Trop d'envois en peu de temps. Patientez quelques minutes.")
            return redirect(request.path)
        form = ChildForm(request.POST)
        if form.is_valid():
            d = form.cleaned_data
            key = (d["nom"].lower(), d["prenom"].lower())
            dup = any((r.nom.lower(), r.prenom.lower()) == key for r in link.registrations.all())
            if dup and not d.get("confirm_duplicate"):
                form.data = form.data.copy()
                form.data["confirm_duplicate"] = "1"
                ctx.update(form=form, duplicate=True)
                return render(request, "public/link_form.html", ctx)
            try:
                reg = _create_registration(link, d)
            except _Full:
                return render(request, "public/link_closed.html", ctx, status=410)
            request.session[session_key] = {k: d.get(k, "") for k in FAMILY_FIELDS}
            request.session[f"last_{link.pk}"] = reg.full_name
            return redirect(request.path + "?ok=1")
    else:
        from .errors import pop_retry

        form = ChildForm(initial={**(request.session.get(session_key) or {}), **pop_retry(request)})

    ctx["form"] = form
    if request.GET.get("ok"):
        ctx["just_added"] = request.session.pop(f"last_{link.pk}", None)
    return render(request, "public/link_form.html", ctx)


class _Full(Exception):
    pass


def _create_registration(link, d):
    with transaction.atomic():
        # Verrou : deux personnes qui valident en même temps ne peuvent pas dépasser le quota.
        locked = RegistrationLink.objects.select_for_update().select_related("event").get(pk=link.pk)
        if not locked.is_usable:
            raise _Full
        data = {k: d.get(k, "") for k in ["nom", "prenom", "parent_name", "parent_phone", "parent_phone2", "paroisse", "charge_name", "charge_phone"]}
        data["nom"] = data["nom"].upper()
        for _ in range(5):
            last = Registration.objects.aggregate(m=Max("reference"))["m"] or 0
            reg = Registration(link=locked, event=locked.event, reference=last + 1, **data)
            reg.qr_fragment = build_fragment(reg.public_id, locked.event.retention_until, {**data, "ref": reg.ref_display})
            try:
                with transaction.atomic():
                    reg.save()
                break
            except IntegrityError:  # collision d'identifiant (quasi impossible) : on retire
                continue
        else:
            raise IntegrityError("Impossible de générer un identifiant unique")
        locked.last_registration_at = timezone.now()
        locked.save(update_fields=["last_registration_at"])
    return reg


# ------------------------------------------------------------------ PWA
@require_GET
@cache_control(max_age=0, no_cache=True)
def service_worker(request):
    from django.templatetags.static import static

    assets = [static(a) for a in SW_ASSETS]
    version = crypto.token_hash("|".join(assets) + crypto.public_key_fingerprint() + SW_REVISION)[:12]
    resp = render(request, "sw.js", {"assets": assets, "version": version}, content_type="application/javascript")
    resp["Service-Worker-Allowed"] = "/"
    return resp


@require_GET
@cache_control(max_age=3600)
def manifest(request):
    return render(request, "manifest.webmanifest", content_type="application/manifest+json")


@require_GET
@cache_control(max_age=3600)
def manifest_gestion(request):
    return render(request, "gestion.webmanifest", content_type="application/manifest+json")


@require_GET
def robots(request):
    return HttpResponse("User-agent: *\nDisallow: /\n", content_type="text/plain")


@require_GET
def offline(request):
    return render(request, "public/offline.html")


def healthz(request):
    """Contrôle de santé Railway : vérifie que la base répond."""
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connection)
    if executor.migration_plan(executor.loader.graph.leaf_nodes()):
        return HttpResponse("migrations en attente", status=503, content_type="text/plain")
    return HttpResponse("ok", content_type="text/plain")
