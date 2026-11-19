"""Accueil de l'administrateur : les gains, ses actions (liens, inscrits) et l'équipe technique.
Il n'a jamais accès aux QR codes ni aux PDF : ce sont les développeurs qui génèrent les bracelets."""
from django.db.models import Count, Sum
from django.shortcuts import render

from ..models import Event, Registration, RegistrationLink, SiteSettings, User
from ..utils import pretty_phone, wa_number
from ..security import role_required


@role_required("gains")
def gains(request):
    rows = []
    for ev in Event.objects.order_by("-starts_on"):
        if ev.is_purged:
            amount, places, nlinks, kids = ev.purged_amount, ev.purged_places, ev.purged_links, ev.purged_registrations
        else:
            t = RegistrationLink.objects.filter(event=ev).aggregate(a=Sum("amount_received"), q=Sum("quota"), n=Count("id"))
            amount, places, nlinks = t["a"] or 0, t["q"] or 0, t["n"]
            kids = Registration.objects.filter(event=ev).count()
        rows.append({"ev": ev, "amount": amount, "places": places, "links": nlinks, "kids": kids,
                     "pct": round(100 * kids / places) if places else 0})
    recent = (
        RegistrationLink.objects.filter(event__purged_at__isnull=True)
        .select_related("event")
        .only("amount_received", "quota", "created_at", "event__title")
        .order_by("-created_at")[:15]
    )
    total = sum(r["amount"] for r in rows)
    fallback = SiteSettings.get().dev_whatsapp
    team = []
    for d in User.objects.filter(kind=User.DEVELOPER, is_active=True).order_by("-is_principal", "full_name"):
        phone = d.phone or (fallback if d.is_principal else "")
        team.append({"name": d.full_name, "title": d.title, "wa": wa_number(phone), "pretty": pretty_phone("+" + wa_number(phone)) if phone else ""})
    return render(request, "espace/gains.html", {
        "nav": "gains", "rows": rows, "recent": recent, "total": total, "team": team,
        "kids": sum(r["kids"] for r in rows), "places": sum(r["places"] for r in rows),
        "payments": sum(r["links"] for r in rows),
    })
