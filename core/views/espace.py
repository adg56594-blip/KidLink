"""Espace de l'administrateur : UNE seule page, « Les gains ».

L'administrateur ne gère rien. Il voit l'argent encaissé et le nombre d'enfants inscrits,
et contacte les développeurs par WhatsApp. Il ne voit aucune donnée d'enfant ni de famille.
"""
from django.db.models import Count, Sum
from django.shortcuts import render

from ..models import Event, Registration, RegistrationLink
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
    return render(request, "espace/gains.html", {
        "nav": "gains", "rows": rows, "recent": recent, "total": total,
        "kids": sum(r["kids"] for r in rows), "places": sum(r["places"] for r in rows),
        "payments": sum(r["links"] for r in rows),
    })
