import getpass

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from core.models import User


class Command(BaseCommand):
    help = "Crée le développeur principal (une seule fois). La double authentification sera demandée à la première connexion."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--name", required=True)
        parser.add_argument("--phone", default="")

    def handle(self, *args, email, name, phone, **opts):
        if User.objects.filter(kind=User.DEVELOPER, is_principal=True).exists():
            raise CommandError("Le développeur principal existe déjà.")
        pwd = getpass.getpass("Mot de passe (12 caractères min.) : ")
        if pwd != getpass.getpass("Confirmer : "):
            raise CommandError("Les mots de passe ne correspondent pas.")
        try:
            validate_password(pwd, User(email=email, full_name=name))
        except ValidationError as e:
            raise CommandError(" ".join(e.messages))
        User.objects.create_user(email=email, password=pwd, full_name=name, phone=phone, kind=User.DEVELOPER, is_principal=True)
        self.stdout.write(self.style.SUCCESS("Développeur principal créé. Connectez-vous sur /connexion/."))
