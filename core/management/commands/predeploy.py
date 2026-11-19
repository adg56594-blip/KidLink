"""Lancée par Railway avant chaque démarrage : migrations, puis lien d'activation
du développeur principal tant que ce compte n'existe pas."""
from datetime import timedelta

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.utils import timezone

from core import crypto
from core.models import Invitation, User


class Command(BaseCommand):
    help = "Migrations + lien d'activation du développeur principal (si absent)."

    def handle(self, *args, **opts):
        call_command("migrate", interactive=False, verbosity=1)
        call_command("createcachetable", verbosity=0)
        if User.objects.filter(kind=User.DEVELOPER, is_principal=True).exists():
            self.stdout.write("Développeur principal déjà présent : aucun lien d'activation créé.")
            return
        # Un seul lien valable à la fois : les anciens sont annulés.
        Invitation.objects.filter(kind=Invitation.LEAD_DEV, used_at__isnull=True).update(revoked=True)
        token = crypto.new_token(32)
        Invitation.objects.create(
            kind=Invitation.LEAD_DEV,
            token_hash=crypto.token_hash(token),
            expires_at=timezone.now() + timedelta(hours=24),
        )
        url = f"{settings.KIDLINK_PUBLIC_URL}/invitation/{token}/"
        bar = "=" * 72
        self.stdout.write(f"\n{bar}\nCRÉATION DU COMPTE DÉVELOPPEUR PRINCIPAL (lien unique, valable 24 h) :\n{url}\n{bar}\n")
