"""Console des développeurs : ils gèrent TOUT (l'administrateur ne fait que regarder les gains)."""
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Count, Q, Sum
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from .. import crypto
from ..forms import EventForm, InviteForm, LinkForm, PurgeForm, RolesForm, SettingsForm, link_expiry
from ..models import AuditLog, Event, Invitation, Registration, RegistrationLink, ScanLog, User
from ..roles import DEV_ROLES, clean_roles
from ..security import lead_dev_required, role_required, two_factor_paused_until
from ..services import pdf_response, purge_event
from ..utils import audit


def ctx(nav, **extra):
    return {"nav": nav, **extra}


def live_links():
    return RegistrationLink.objects.filter(event__purged_at__isnull=True)


# ================================================================== tableau de bord
def dashboard(request):
    now = timezone.now()
    links = live_links()
    totals = links.aggregate(q=Sum("quota"), a=Sum("amount_received"))
    filled = Registration.objects.filter(event__purged_at__isnull=True).count()
    places = totals["q"] or 0
    checks = [
        ("Mode production (DEBUG désactivé)", not settings.DEBUG),
        ("Clé de chiffrement fournie par l'environnement", bool(settings.KIDLINK_FIELD_KEYS)),
        ("Clé de signature fournie par l'environnement", bool(settings.KIDLINK_SIGNING_KEY)),
        ("Adresse publique en HTTPS", settings.KIDLINK_PUBLIC_URL.startswith("https://")),
        ("Double authentification active (pas de pause de test)", not two_factor_paused_until()),
        ("Compte administrateur créé", User.objects.filter(kind=User.ADMIN, is_principal=True).exists()),
    ]
    data = {
        "featured": Event.featured().annotate(n=Count("registrations")).first(),
        "places": places,
        "filled": filled,
        "pending": max(places - filled, 0),
        "fill_pct": round(100 * filled / places) if places else 0,
        "cash": totals["a"] or 0,
        "links_active": links.filter(is_active=True).count(),
        "recent_links": links.select_related("event").annotate(n=Count("registrations"))[:5],
        "scans_week": ScanLog.objects.filter(created_at__gte=now - timedelta(days=7)).count(),
        "forged_week": ScanLog.objects.filter(result=ScanLog.FORGED, created_at__gte=now - timedelta(days=7)).count(),
        "checks": checks,
        "fingerprint": crypto.public_key_fingerprint(),
    }
    return render(request, "dev/dashboard.html", ctx("dashboard", **data))


# ================================================================== pèlerinages
@role_required("events", "purge")
def events(request):
    evs = Event.objects.annotate(n=Count("registrations"), nl=Count("links", distinct=True))
    return render(request, "dev/events.html", ctx("events", events=evs, today=timezone.localdate()))


@role_required("events")
@require_http_methods(["GET", "POST"])
def event_edit(request, pk=None):
    ev = get_object_or_404(Event, pk=pk, purged_at__isnull=True) if pk else None
    form = EventForm(request.POST or None, instance=ev)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        if not ev:
            obj.created_by = request.user
        obj.save()
        audit(request, "event_saved", f"{obj.pk} · {obj.title}")
        messages.success(request, "Pèlerinage enregistré.")
        return redirect("dev:events")
    return render(request, "dev/event_form.html", ctx("events", form=form, ev=ev))


@role_required("purge")
@require_http_methods(["GET", "POST"])
def event_purge(request, pk):
    ev = get_object_or_404(Event, pk=pk, purged_at__isnull=True)
    allowed = ev.retention_over or request.user.is_lead_dev
    form = PurgeForm(request.POST or None)
    if request.method == "POST":
        if not allowed:
            raise PermissionDenied
        if form.is_valid():
            n = purge_event(ev, request.user)
            audit(request, "event_purged", f"{ev.pk} · {ev.title} · {n} inscription(s) effacée(s)")
            messages.success(request, f"Données effacées : {n} inscription(s).")
            return redirect("dev:events")
    return render(request, "dev/event_purge.html", ctx("events", ev=ev, form=form, allowed=allowed, count=ev.registrations.count()))


# ================================================================== liens d'inscription
@role_required("links", "registrations", "documents")
def links(request):
    qs = live_links().select_related("event").annotate(n=Count("registrations"))
    q = request.GET.get("q", "").strip()[:60]
    if q:
        qs = qs.filter(Q(label__icontains=q) | Q(event__title__icontains=q))
    return render(request, "dev/links.html", ctx("links", links=qs, q=q))


@role_required("links")
@require_http_methods(["GET", "POST"])
def link_create(request):
    form = LinkForm(request.POST or None)
    if not form.fields["event"].queryset.exists():
        messages.warning(request, "Créez d'abord le pèlerinage.")
        return redirect("dev:events")
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        token = crypto.new_token(24)
        link = RegistrationLink.objects.create(
            event=d["event"], label=d["label"], payer_name=d["payer_name"], payer_phone=d["payer_phone"],
            quota=d["quota"], amount_received=d["amount_received"],
            token_hash=crypto.token_hash(token), token_hint=token[-4:],
            expires_at=link_expiry(d["valid_days"]), created_by=request.user,
        )
        audit(request, "link_created", f"{link.pk} · {link.label} · {link.quota} place(s) · {link.amount_received} F")
        request.session[f"newlink_{link.pk}"] = token
        return redirect("dev:link_detail", pk=link.pk)
    prices = {str(e.pk): e.price_per_child for e in form.fields["event"].queryset}
    return render(request, "dev/link_form.html", ctx("new", form=form, prices=prices))


@role_required("links", "registrations", "documents")
def link_detail(request, pk):
    link = get_object_or_404(live_links().select_related("event", "created_by"), pk=pk)
    token = request.session.pop(f"newlink_{link.pk}", None) if request.user.has_role("links") else None
    url = f"{settings.KIDLINK_PUBLIC_URL}/i/{token}/" if token else None
    regs = list(link.registrations.all()) if request.user.has_role("registrations") else None
    share = None
    if url:
        share = (
            f"Bonjour {link.payer_name}, voici votre lien Sèmè Kids pour inscrire {link.quota} enfant(s) "
            f"au {link.event.title} : {url}  Remplissez une fiche par enfant. Ce lien est personnel, ne le partagez pas."
        )
    return render(request, "dev/link_detail.html", ctx("links", link=link, url=url, share=share, regs=regs))


@role_required("links")
@require_POST
def link_toggle(request, pk):
    link = get_object_or_404(live_links(), pk=pk)
    link.is_active = not link.is_active
    link.save(update_fields=["is_active"])
    audit(request, "link_toggled", f"{link.pk} · actif={link.is_active}")
    messages.success(request, "Lien réactivé." if link.is_active else "Lien désactivé : plus personne ne peut l'utiliser.")
    return redirect("dev:link_detail", pk=pk)


@role_required("links")
@require_POST
def link_regenerate(request, pk):
    link = get_object_or_404(live_links(), pk=pk)
    token = crypto.new_token(24)
    link.token_hash = crypto.token_hash(token)
    link.token_hint = token[-4:]
    link.expires_at = max(link.expires_at, link_expiry(3))
    link.save(update_fields=["token_hash", "token_hint", "expires_at"])
    audit(request, "link_regenerated", str(link.pk))
    request.session[f"newlink_{link.pk}"] = token
    messages.success(request, "Nouveau lien créé. L'ancien ne fonctionne plus.")
    return redirect("dev:link_detail", pk=pk)


@role_required("registrations")
@require_POST
def registration_revoke(request, pk):
    reg = get_object_or_404(Registration, pk=pk, event__purged_at__isnull=True)
    reg.revoked_at = None if reg.revoked_at else timezone.now()
    reg.save(update_fields=["revoked_at"])
    audit(request, "bracelet_revoked" if reg.revoked_at else "bracelet_restored", reg.public_id)
    messages.success(request, "Bracelet désactivé." if reg.revoked_at else "Bracelet réactivé.")
    return redirect("dev:link_detail", pk=reg.link_id)


# ================================================================== bracelets (PDF)
@role_required("documents")
def bracelets(request):
    rows = live_links().select_related("event").annotate(n=Count("registrations")).filter(n__gt=0)
    return render(request, "dev/bracelets.html", ctx("bracelets", rows=rows))


@role_required("documents")
def pdf_download(request, pk):
    link = get_object_or_404(live_links().select_related("event"), pk=pk)
    return pdf_response(link, request)


# ================================================================== compte de l'administrateur
@role_required("accounts")
def accounts(request):
    admins = User.objects.filter(kind=User.ADMIN).order_by("-is_principal", "full_name")
    has_admin = admins.filter(is_principal=True).exists()
    invites = Invitation.objects.filter(kind=Invitation.PRINCIPAL_ADMIN, used_at__isnull=True, revoked=False, expires_at__gt=timezone.now())
    url = request.session.pop("principal_invite_url", None)
    return render(request, "dev/accounts.html", ctx("accounts", admins=admins, has_admin=has_admin, invites=invites, invite_url=url))


@role_required("accounts")
@require_POST
def principal_invite(request):
    if User.objects.filter(kind=User.ADMIN, is_principal=True).exists():
        messages.error(request, "Le compte administrateur existe déjà.")
        return redirect("dev:accounts")
    Invitation.objects.filter(kind=Invitation.PRINCIPAL_ADMIN, used_at__isnull=True).update(revoked=True)
    token = crypto.new_token(32)
    Invitation.objects.create(
        kind=Invitation.PRINCIPAL_ADMIN,
        email=(request.POST.get("email") or "").strip().lower()[:254],
        full_name=(request.POST.get("full_name") or "").strip()[:120],
        token_hash=crypto.token_hash(token),
        created_by=request.user,
        expires_at=timezone.now() + timedelta(hours=48),
    )
    audit(request, "principal_invited")
    request.session["principal_invite_url"] = f"{settings.KIDLINK_PUBLIC_URL}/inscription-administrateur/{token}/"
    return redirect("dev:accounts")


@role_required("accounts")
@require_POST
def account_action(request, pk):
    user = get_object_or_404(User, pk=pk, kind=User.ADMIN)
    action = request.POST.get("action")
    if action == "toggle":
        user.is_active = not user.is_active
        user.save(update_fields=["is_active"])
    elif action == "reset_2fa":
        # Effacement volontaire du secret 2FA (faux positif bandit).
        user.totp_secret = ""  # nosec B105
        user.totp_confirmed = False
        user.totp_last_step = 0
        user.save(update_fields=["totp_secret", "totp_confirmed", "totp_last_step"])
    else:
        return redirect("dev:accounts")
    audit(request, f"admin_{action}", user.email)
    messages.success(request, "Action effectuée.")
    return redirect("dev:accounts")


# ================================================================== équipe technique
@lead_dev_required
@require_http_methods(["GET", "POST"])
def team(request):
    members = User.objects.filter(kind=User.DEVELOPER, is_principal=False).order_by("full_name")
    invites = Invitation.objects.filter(kind=Invitation.SUB_DEV, used_at__isnull=True, revoked=False, expires_at__gt=timezone.now())
    form = InviteForm(request.POST or None, role_choices=DEV_ROLES)
    invite_url = None
    if request.method == "POST" and form.is_valid():
        token = crypto.new_token(24)
        Invitation.objects.create(
            kind=Invitation.SUB_DEV,
            email=form.cleaned_data["email"],
            full_name=form.cleaned_data["full_name"],
            roles=clean_roles(form.cleaned_data["roles"], DEV_ROLES),
            token_hash=crypto.token_hash(token),
            created_by=request.user,
            expires_at=timezone.now() + timedelta(hours=72),
        )
        audit(request, "subdev_invited", form.cleaned_data["email"])
        invite_url = f"{settings.KIDLINK_PUBLIC_URL}/invitation/{token}/"
        form = InviteForm(role_choices=DEV_ROLES)
    return render(request, "dev/team.html", ctx("team", members=members, invites=invites, form=form, invite_url=invite_url))


@lead_dev_required
@require_http_methods(["GET", "POST"])
def team_member(request, pk):
    member = get_object_or_404(User, pk=pk, kind=User.DEVELOPER, is_principal=False)
    form = RolesForm(request.POST or None, role_choices=DEV_ROLES, initial={"roles": member.roles})
    if request.method == "POST":
        if request.POST.get("action") == "toggle":
            member.is_active = not member.is_active
            member.save(update_fields=["is_active"])
            audit(request, "subdev_toggled", f"{member.email} actif={member.is_active}")
        elif form.is_valid():
            member.roles = clean_roles(form.cleaned_data["roles"], DEV_ROLES)
            member.save(update_fields=["roles"])
            audit(request, "subdev_roles", f"{member.email} : {', '.join(member.roles)}")
        messages.success(request, "Modifications enregistrées.")
        return redirect("dev:team")
    return render(request, "dev/team_member.html", ctx("team", member=member, form=form))


@lead_dev_required
@require_POST
def invite_revoke(request, pk):
    inv = get_object_or_404(Invitation, pk=pk)
    inv.revoked = True
    inv.save(update_fields=["revoked"])
    audit(request, "invite_revoked", inv.email or inv.kind)
    return redirect("dev:accounts" if inv.kind == Invitation.PRINCIPAL_ADMIN else "dev:team")


# ================================================================== journal & réglages
@role_required("audit")
def audit_log(request):
    qs = AuditLog.objects.all()
    q = request.GET.get("q", "").strip()[:60]
    if q:
        qs = qs.filter(Q(action__icontains=q) | Q(detail__icontains=q) | Q(actor_label__icontains=q))
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    return render(request, "dev/audit.html", ctx("audit", page=page, q=q))


@role_required("settings")
@require_http_methods(["GET", "POST"])
def site_settings(request):
    from ..models import SiteSettings

    form = SettingsForm(request.POST or None, instance=SiteSettings.get())
    if request.method == "POST" and form.is_valid():
        form.save()
        audit(request, "settings_updated")
        messages.success(request, "Réglages enregistrés.")
        return redirect("dev:settings")
    return render(request, "dev/settings.html", ctx("settings", form=form, fingerprint=crypto.public_key_fingerprint()))
