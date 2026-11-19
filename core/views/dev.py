"""Console des développeurs."""
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from .. import crypto
from ..forms import DeliveryForm, InviteForm, RolesForm, SettingsForm
from ..models import AuditLog, Event, Invitation, Registration, RegistrationLink, ScanLog, SiteSettings, User
from ..roles import DEV_ASSIGNABLE, clean_roles
from ..security import lead_dev_required, role_required, two_factor_paused_until
from ..utils import audit
from .espace import pdf_response


def ctx(nav, **extra):
    return {"nav": nav, **extra}


def dashboard(request):
    now = timezone.now()
    links = RegistrationLink.objects.filter(event__purged_at__isnull=True).annotate(n=Count("registrations"))
    pending = [l for l in links if l.n and not l.is_released]
    checks = [
        ("Mode production (DEBUG désactivé)", not settings.DEBUG),
        ("Clé de chiffrement fournie par l'environnement", bool(settings.KIDLINK_FIELD_KEYS)),
        ("Clé de signature fournie par l'environnement", bool(settings.KIDLINK_SIGNING_KEY)),
        ("Adresse publique en HTTPS", settings.KIDLINK_PUBLIC_URL.startswith("https://")),
        ("Double authentification active (pas de pause de test)", not two_factor_paused_until()),
        ("Administrateur principal créé", User.objects.filter(kind=User.ADMIN, is_principal=True).exists()),
    ]
    data = {
        "registrations": Registration.objects.count(),
        "pending": pending[:8],
        "pending_count": len(pending),
        "forged_week": ScanLog.objects.filter(result=ScanLog.FORGED, created_at__gte=now - timedelta(days=7)).count(),
        "scans_week": ScanLog.objects.filter(created_at__gte=now - timedelta(days=7)).count(),
        "checks": checks,
        "fingerprint": crypto.public_key_fingerprint(),
        "events": Event.featured().count(),
        "recent": AuditLog.objects.select_related("actor")[:8] if request.user.has_role("audit") else [],
    }
    return render(request, "dev/dashboard.html", ctx("dashboard", **data))


# ------------------------------------------------------------------ livraisons
@role_required("deliveries", "dev_documents")
def deliveries(request):
    qs = RegistrationLink.objects.select_related("event").annotate(n=Count("registrations")).filter(event__purged_at__isnull=True)
    f = request.GET.get("f", "pending")
    rows = list(qs)
    if f == "pending":
        rows = [l for l in rows if l.n and not l.is_released]
    elif f == "released":
        rows = [l for l in rows if l.is_released]
    return render(request, "dev/deliveries.html", ctx("deliveries", rows=rows, f=f, modes=SiteSettings.DELIVERY_MODES))


@role_required("deliveries")
@require_http_methods(["GET", "POST"])
def delivery_edit(request, pk):
    link = get_object_or_404(RegistrationLink.objects.select_related("event"), pk=pk, event__purged_at__isnull=True)
    initial = {
        "mode": link.delivery_mode,
        "delay_hours": link.delivery_delay_hours,
        "scheduled_at": timezone.localtime(link.delivery_scheduled_at).strftime("%Y-%m-%dT%H:%M") if link.delivery_scheduled_at else None,
    }
    form = DeliveryForm(request.POST or None, initial=initial)
    if request.method == "POST":
        if request.POST.get("action") == "now":
            link.delivery_mode = SiteSettings.IMMEDIATE
            link.delivery_updated_by = request.user
            link.save(update_fields=["delivery_mode", "delivery_updated_by"])
            audit(request, "delivery_released", str(link.pk))
            messages.success(request, "PDF livré à l'administration.")
            return redirect("dev:deliveries")
        if form.is_valid():
            d = form.cleaned_data
            link.delivery_mode = d["mode"]
            if d.get("delay_hours"):
                link.delivery_delay_hours = d["delay_hours"]
            link.delivery_scheduled_at = d.get("scheduled_at") if d["mode"] == SiteSettings.SCHEDULED else None
            link.delivery_updated_by = request.user
            link.save(update_fields=["delivery_mode", "delivery_delay_hours", "delivery_scheduled_at", "delivery_updated_by"])
            audit(request, "delivery_updated", f"{link.pk} · {link.get_delivery_mode_display()}")
            messages.success(request, "Règle d'envoi enregistrée.")
            return redirect("dev:deliveries")
    return render(request, "dev/delivery_edit.html", ctx("deliveries", link=link, form=form))


@role_required("deliveries")
@require_POST
def deliveries_bulk(request):
    ids = [int(i) for i in request.POST.getlist("ids") if i.isdigit()][:500]
    mode = request.POST.get("mode")
    if mode not in dict(SiteSettings.DELIVERY_MODES) or mode == SiteSettings.SCHEDULED:
        messages.error(request, "Choix invalide.")
        return redirect("dev:deliveries")
    n = RegistrationLink.objects.filter(pk__in=ids, event__purged_at__isnull=True).update(delivery_mode=mode, delivery_updated_by=request.user)
    audit(request, "delivery_bulk", f"{n} lot(s) → {mode}")
    messages.success(request, f"{n} lot(s) mis à jour.")
    return redirect("dev:deliveries")


@role_required("dev_documents")
def pdf_download(request, pk):
    link = get_object_or_404(RegistrationLink.objects.select_related("event"), pk=pk, event__purged_at__isnull=True)
    return pdf_response(link, request)


# ------------------------------------------------------------------ comptes administrateurs
@role_required("accounts")
def accounts(request):
    admins = User.objects.filter(kind=User.ADMIN).order_by("-is_principal", "full_name")
    has_principal = admins.filter(is_principal=True).exists()
    invites = Invitation.objects.filter(kind=Invitation.PRINCIPAL_ADMIN, used_at__isnull=True, revoked=False, expires_at__gt=timezone.now())
    url = request.session.pop("principal_invite_url", None)
    return render(request, "dev/accounts.html", ctx("accounts", admins=admins, has_principal=has_principal, invites=invites, invite_url=url))


@role_required("accounts")
@require_POST
def principal_invite(request):
    if User.objects.filter(kind=User.ADMIN, is_principal=True).exists():
        messages.error(request, "L'administrateur principal existe déjà.")
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


# ------------------------------------------------------------------ équipe développeurs
@lead_dev_required
@require_http_methods(["GET", "POST"])
def team(request):
    members = User.objects.filter(kind=User.DEVELOPER, is_principal=False).order_by("full_name")
    invites = Invitation.objects.filter(kind=Invitation.SUB_DEV, used_at__isnull=True, revoked=False, expires_at__gt=timezone.now())
    form = InviteForm(request.POST or None, role_choices=DEV_ASSIGNABLE)
    invite_url = None
    if request.method == "POST" and form.is_valid():
        token = crypto.new_token(24)
        Invitation.objects.create(
            kind=Invitation.SUB_DEV,
            email=form.cleaned_data["email"],
            full_name=form.cleaned_data["full_name"],
            roles=clean_roles(form.cleaned_data["roles"], DEV_ASSIGNABLE),
            token_hash=crypto.token_hash(token),
            created_by=request.user,
            expires_at=timezone.now() + timedelta(hours=72),
        )
        audit(request, "subdev_invited", form.cleaned_data["email"])
        invite_url = f"{settings.KIDLINK_PUBLIC_URL}/invitation/{token}/"
        form = InviteForm(role_choices=DEV_ASSIGNABLE)
    return render(request, "dev/team.html", ctx("team", members=members, invites=invites, form=form, invite_url=invite_url))


@lead_dev_required
@require_http_methods(["GET", "POST"])
def team_member(request, pk):
    member = get_object_or_404(User, pk=pk, kind=User.DEVELOPER, is_principal=False)
    form = RolesForm(request.POST or None, role_choices=DEV_ASSIGNABLE, initial={"roles": member.roles})
    if request.method == "POST":
        if request.POST.get("action") == "toggle":
            member.is_active = not member.is_active
            member.save(update_fields=["is_active"])
            audit(request, "subdev_toggled", f"{member.email} actif={member.is_active}")
        elif form.is_valid():
            member.roles = clean_roles(form.cleaned_data["roles"], DEV_ASSIGNABLE)
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
    return redirect(request.POST.get("back") == "accounts" and "dev:accounts" or "dev:team")


# ------------------------------------------------------------------ journal & réglages
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
    s = SiteSettings.get()
    form = SettingsForm(request.POST or None, instance=s)
    if request.method == "POST" and form.is_valid():
        form.save()
        audit(request, "settings_updated")
        messages.success(request, "Réglages enregistrés.")
        return redirect("dev:settings")
    return render(request, "dev/settings.html", ctx("settings", form=form, fingerprint=crypto.public_key_fingerprint()))
