"""Secours : lien « nouveau mot de passe » pour N'IMPORTE QUEL compte, y compris le développeur
principal (qui n'a personne au-dessus de lui dans la console). Ne fonctionne que depuis le serveur
(ex. « railway ssh » puis « python manage.py reset_password --email … »)."""
from django.core.management.base import BaseCommand, CommandError

from core.models import AuditLog, User
from core.services import RESET_LINK_HOURS, create_password_reset_link


class Command(BaseCommand):
    help = "Crée un lien unique (24 h) pour choisir un nouveau mot de passe. --reset-2fa : nouveau code de sécurité aussi."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--reset-2fa", action="store_true", help="Le compte devra scanner un nouveau QR code (téléphone perdu).")

    def handle(self, *args, email, reset_2fa, **opts):
        user = User.objects.filter(email__iexact=email.strip()).first()
        if user is None:
            raise CommandError("Aucun compte avec cette adresse.")
        if reset_2fa:
            user.totp_secret = ""  # nosec B105
            user.totp_confirmed = False
            user.totp_last_step = 0
            user.save(update_fields=["totp_secret", "totp_confirmed", "totp_last_step"])
        url = create_password_reset_link(user)
        AuditLog.objects.create(action="password_reset_link_cli", detail=f"{user.email} 2fa={'oui' if reset_2fa else 'non'}")
        self.stdout.write(f"Lien pour {user.full_name} ({user.title}), valable {RESET_LINK_HOURS} h, une seule fois :\n{url}")
