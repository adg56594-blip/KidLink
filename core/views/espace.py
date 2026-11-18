"""Espace administration (administrateur principal et sous-administrateurs)."""
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Count, Q, Sum
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.text import slugify
from django.views.decorators.http import require_POST

from .. import crypto
from ..forms import EventForm, InviteForm, LinkForm, PurgeForm, RolesForm, link_expiry
from ..models import Event, Invitation, Registration, RegistrationLink, ScanLog, SiteSettings, User
from ..pdf import build_pdf
from ..roles import ADMIN_ROLES, clean_roles
from ..security import principal_admin_required, role_required
from ..utils import audit


def ctx(request, nav, **extra):
    return {"nav": nav, **extra}


# ------------------------------------------------------------------ tableau de bord
def dashboard(request):
    links = RegistrationLink.objects.filter(event__purged_at__isnull=True)
    places = links.aggregate(q=Sum("quota"), a=Sum("amount_received"))
    filled = Registration.objects.filter(event__purged_at__isnull=True).count()
    week_ago = timezone.now() - timedelta(days=7)
    featured = Event.featured().annotate(n=Count("registrations")).first()
    data = {
        "events_live": Event.featured().count(),
        "links_active": links.filter(is_active=True).count(),
        "places": places["q"] or 0,
        "cash": places["a"] or 0,
        "filled": filled,
        "pending": max((places["q"] or 0) - filled, 0),
        "scans_week": ScanLog.objects.filter(created_at__gte=week_ago, result=ScanLog.VALID).count(),
        "recent_links": links.select_related("event").annotate(n=Count("registrations"))[:6],
        "featured": featured,
        "documents_ready": sum(1 for l in links.exclude(last_registration_at=None) if l.is_released),
    }
    data["fill_pct"] = round(100 * filled / data["places"]) if data["places"] else 0
    return render(request, "espace/dashboard.html", ctx(request, "dashboard", **data))


# ------------------------------------------------------------------ événements
@role_required("events", "purge")
def events(request):
    evs = Event.objects.annotate(n=Count("registrations"), nl=Count("links", distinct=True))
    return render(request, "espace/events.html", ctx(request, "events", events=evs, today=timezone.localdate()))


@role_required("events")
def event_edit(request, pk=None):
    ev = get_object_or_404(Event, pk=pk, purged_at__isnull=True) if pk else None
    form = EventForm(request.POST or None, instance=ev)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        if not ev:
            obj.created_by = request.user
        obj.save()
        audit(request, "event_saved", f"{obj.pk} · {obj.title}")
        messages.success(request, "Événement enregistré.")
        return redirect("espace:events")
    return render(request, "espace/event_form.html", ctx(request, "events", form=form, ev=ev))


@role_required("purge")
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
            return redirect("espace:events")
    count = ev.registrations.count()
    return render(request, "espace/event_purge.html", ctx(request, "events", ev=ev, form=form, allowed=allowed, count=count))


def purge_event(ev, user=None):
    with transaction.atomic():
        n = ev.registrations.count()
        ScanLog.objects.filter(registration__event=ev).delete()
        ev.registrations.all().delete()
        ev.links.all().delete()
        ev.purged_at = timezone.now()
        ev.purged_by = user
        ev.purged_registrations = n
        ev.save(update_fields=["purged_at", "purged_by", "purged_registrations"])
    return n


# ------------------------------------------------------------------ liens
@role_required("links", "registrations", "documents")
def links(request):
    qs = RegistrationLink.objects.select_related("event").annotate(n=Count("registrations")).filter(event__purged_at__isnull=True)
    q = request.GET.get("q", "").strip()[:60]
    if q:
        qs = qs.filter(Q(label__icontains=q) | Q(event__title__icontains=q))
    return render(request, "espace/links.html", ctx(request, "links", links=qs, q=q))


@role_required("links")
def link_create(request):
    form = LinkForm(request.POST or None)
    if not form.fields["event"].queryset.exists():
        messages.warning(request, "Créez d'abord un événement à venir.")
        return redirect("espace:events")
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        token = crypto.new_token(24)
        s = SiteSettings.get()
        link = RegistrationLink.objects.create(
            event=d["event"],
            label=d["label"],
            payer_name=d["payer_name"],
            payer_phone=d["payer_phone"],
            quota=d["quota"],
            amount_received=d["amount_received"],
            token_hash=crypto.token_hash(token),
            token_hint=token[-4:],
            expires_at=link_expiry(d["valid_days"]),
            created_by=request.user,
            delivery_mode=s.default_delivery_mode,
            delivery_delay_hours=s.default_delay_hours,
        )
        audit(request, "link_created", f"{link.pk} · {link.label} · {link.quota} place(s) · {link.amount_received} F")
        request.session[f"newlink_{link.pk}"] = token
        return redirect("espace:link_detail", pk=link.pk)
    events_prices = {str(e.pk): e.price_per_child for e in form.fields["event"].queryset}
    return render(request, "espace/link_form.html", ctx(request, "links", form=form, prices=events_prices))


@role_required("links", "registrations", "documents")
def link_detail(request, pk):
    link = get_object_or_404(RegistrationLink.objects.select_related("event", "created_by"), pk=pk, event__purged_at__isnull=True)
    token = request.session.pop(f"newlink_{link.pk}", None) if request.user.has_role("links") else None
    url = f"{settings.KIDLINK_PUBLIC_URL}/i/{token}/" if token else None
    regs = list(link.registrations.all()) if request.user.has_role("registrations") else None
    share = None
    if url:
        share = (
            f"Bonjour {link.payer_name}, voici votre lien Sèmè Kids pour inscrire {link.quota} enfant(s) "
            f"au {link.event.title} : {url}  Remplissez une fiche par enfant. Ce lien est personnel, ne le partagez pas."
        )
    return render(request, "espace/link_detail.html", ctx(request, "links", link=link, url=url, share=share, regs=regs))


@role_required("links")
@require_POST
def link_toggle(request, pk):
    link = get_object_or_404(RegistrationLink, pk=pk, event__purged_at__isnull=True)
    link.is_active = not link.is_active
    link.save(update_fields=["is_active"])
    audit(request, "link_toggled", f"{link.pk} · actif={link.is_active}")
    messages.success(request, "Lien réactivé." if link.is_active else "Lien désactivé : plus personne ne peut l'utiliser.")
    return redirect("espace:link_detail", pk=pk)


@role_required("links")
@require_POST
def link_regenerate(request, pk):
    link = get_object_or_404(RegistrationLink, pk=pk, event__purged_at__isnull=True)
    token = crypto.new_token(24)
    link.token_hash = crypto.token_hash(token)
    link.token_hint = token[-4:]
    link.expires_at = max(link.expires_at, link_expiry(3))
    link.save(update_fields=["token_hash", "token_hint", "expires_at"])
    audit(request, "link_regenerated", str(link.pk))
    request.session[f"newlink_{link.pk}"] = token
    messages.success(request, "Nouveau lien créé. L'ancien ne fonctionne plus.")
    return redirect("espace:link_detail", pk=pk)


@role_required("registrations")
@require_POST
def registration_revoke(request, pk):
    reg = get_object_or_404(Registration, pk=pk, event__purged_at__isnull=True)
    reg.revoked_at = None if reg.revoked_at else timezone.now()
    reg.save(update_fields=["revoked_at"])
    audit(request, "bracelet_revoked" if reg.revoked_at else "bracelet_restored", reg.public_id)
    messages.success(request, "Bracelet désactivé." if reg.revoked_at else "Bracelet réactivé.")
    return redirect("espace:link_detail", pk=reg.link_id)


# ------------------------------------------------------------------ documents
@role_required("documents")
def documents(request):
    qs = RegistrationLink.objects.select_related("event").annotate(n=Count("registrations")).filter(event__purged_at__isnull=True, n__gt=0)
    ready = [l for l in qs if l.is_released]
    waiting = len(qs) - len(ready)
    return render(request, "espace/documents.html", ctx(request, "documents", ready=ready, waiting=waiting))


def pdf_response(link, request):
    regs = link.registrations.filter(revoked_at__isnull=True)
    data = build_pdf(regs, title=link.event.title, subtitle=link.label, bracelet_line=SiteSettings.get().bracelet_line)
    resp = HttpResponse(data, content_type="application/pdf")
    name = slugify(f"bracelets-{link.event.title}-{link.label}")[:80] or "bracelets"
    resp["Content-Disposition"] = f'attachment; filename="{name}.pdf"'
    resp["Cache-Control"] = "no-store, private"
    audit(request, "pdf_downloaded", f"{link.pk} · {regs.count()} bracelet(s)")
    return resp


@role_required("documents")
def document_download(request, pk):
    link = get_object_or_404(RegistrationLink.objects.select_related("event"), pk=pk, event__purged_at__isnull=True)
    if not link.is_released and not request.user.has_role("dev_documents"):
        raise PermissionDenied  # pas encore livré par les développeurs
    return pdf_response(link, request)


# ------------------------------------------------------------------ équipe (admin principal)
@principal_admin_required
def team(request):
    members = User.objects.filter(kind=User.ADMIN, is_principal=False).order_by("full_name")
    invites = Invitation.objects.filter(kind=Invitation.SUB_ADMIN, used_at__isnull=True, revoked=False, expires_at__gt=timezone.now())
    form = InviteForm(request.POST or None, role_choices=ADMIN_ROLES)
    invite_url = None
    if request.method == "POST" and form.is_valid():
        token = crypto.new_token(24)
        Invitation.objects.create(
            kind=Invitation.SUB_ADMIN,
            email=form.cleaned_data["email"],
            full_name=form.cleaned_data["full_name"],
            roles=clean_roles(form.cleaned_data["roles"], ADMIN_ROLES),
            token_hash=crypto.token_hash(token),
            created_by=request.user,
            expires_at=timezone.now() + timedelta(hours=72),
        )
        audit(request, "subadmin_invited", form.cleaned_data["email"])
        invite_url = f"{settings.KIDLINK_PUBLIC_URL}/invitation/{token}/"
        form = InviteForm(role_choices=ADMIN_ROLES)
    return render(
        request,
        "espace/team.html",
        ctx(request, "team", members=members, invites=invites, form=form, invite_url=invite_url, roles=ADMIN_ROLES),
    )


@principal_admin_required
def team_member(request, pk):
    member = get_object_or_404(User, pk=pk, kind=User.ADMIN, is_principal=False)
    form = RolesForm(request.POST or None, role_choices=ADMIN_ROLES, initial={"roles": member.roles})
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "toggle":
            member.is_active = not member.is_active
            member.save(update_fields=["is_active"])
            audit(request, "subadmin_toggled", f"{member.email} actif={member.is_active}")
        elif form.is_valid():
            member.roles = clean_roles(form.cleaned_data["roles"], ADMIN_ROLES)
            member.save(update_fields=["roles"])
            audit(request, "subadmin_roles", f"{member.email} : {', '.join(member.roles)}")
        messages.success(request, "Modifications enregistrées.")
        return redirect("espace:team")
    return render(request, "espace/team_member.html", ctx(request, "team", member=member, form=form))


@principal_admin_required
@require_POST
def invite_revoke(request, pk):
    inv = get_object_or_404(Invitation, pk=pk, kind=Invitation.SUB_ADMIN)
    inv.revoked = True
    inv.save(update_fields=["revoked"])
    audit(request, "invite_revoked", inv.email)
    return redirect("espace:team")
