from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import AuditLog, Event
from core.services import purge_event


class Command(BaseCommand):
    help = (
        "Filet de sécurité : efface les données des événements dont la durée de conservation est dépassée "
        "depuis plus de --grace jours et que l'administration n'a pas vidés. À lancer chaque nuit (cron)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--grace", type=int, default=15)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, grace, dry_run, **opts):
        limit = timezone.localdate() - timedelta(days=grace)
        for ev in Event.objects.filter(purged_at__isnull=True):
            if ev.retention_until < limit:
                if dry_run:
                    self.stdout.write(f"[simulation] {ev.title} : {ev.registrations.count()} inscription(s)")
                    continue
                n = purge_event(ev)
                AuditLog.objects.create(action="event_auto_purged", detail=f"{ev.pk} · {ev.title} · {n}")
                self.stdout.write(f"Effacé : {ev.title} ({n})")
