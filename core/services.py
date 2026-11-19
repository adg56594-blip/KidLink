"""Opérations partagées (console, commandes de gestion)."""
from django.db import transaction
from django.db.models import Sum
from django.http import HttpResponse
from django.utils import timezone
from django.utils.text import slugify

from .models import ScanLog, SiteSettings
from .pdf import build_pdf
from .utils import audit


def purge_event(ev, user=None):
    """Efface définitivement les enfants, liens et scans d'un événement.
    Les totaux (argent, places, liens) sont conservés pour la page « Les gains »."""
    with transaction.atomic():
        links = ev.links.all()
        totals = links.aggregate(a=Sum("amount_received"), q=Sum("quota"))
        n = ev.registrations.count()
        ev.purged_amount = totals["a"] or 0
        ev.purged_places = totals["q"] or 0
        ev.purged_links = links.count()
        ScanLog.objects.filter(registration__event=ev).delete()
        ev.registrations.all().delete()
        links.delete()
        ev.purged_at = timezone.now()
        ev.purged_by = user
        ev.purged_registrations = n
        ev.save(update_fields=["purged_at", "purged_by", "purged_registrations", "purged_amount", "purged_places", "purged_links"])
    return n


def pdf_response(link, request):
    regs = link.registrations.filter(revoked_at__isnull=True)
    data = build_pdf(regs, title=link.event.title, subtitle=link.label, bracelet_line=SiteSettings.get().bracelet_line)
    resp = HttpResponse(data, content_type="application/pdf")
    name = slugify(f"bracelets-{link.event.title}-{link.label}")[:80] or "bracelets"
    resp["Content-Disposition"] = f'attachment; filename="{name}.pdf"'
    resp["Cache-Control"] = "no-store, private"
    audit(request, "pdf_downloaded", f"{link.pk} · {regs.count()} bracelet(s)")
    return resp
