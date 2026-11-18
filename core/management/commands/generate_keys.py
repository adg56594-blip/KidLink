from django.core.management.base import BaseCommand
from django.core.management.utils import get_random_secret_key

from core.crypto import new_field_key, new_signing_key_pem


class Command(BaseCommand):
    help = "Affiche de nouvelles clés à placer dans les variables d'environnement de production."

    def handle(self, *args, **opts):
        pem = new_signing_key_pem().strip().replace("\n", "\\n")
        self.stdout.write("# À conserver dans un coffre-fort. Ne jamais les committer.\n")
        self.stdout.write(f"DJANGO_SECRET_KEY='{get_random_secret_key()}'")
        self.stdout.write(f"KIDLINK_FIELD_KEYS='{new_field_key()}'")
        self.stdout.write(f"KIDLINK_SIGNING_KEY='{pem}'")
        self.stdout.write(
            "\n# ATTENTION : changer KIDLINK_SIGNING_KEY rend invalides tous les bracelets déjà imprimés.\n"
            "# Pour changer KIDLINK_FIELD_KEYS, placez la nouvelle clé EN PREMIER suivie de l'ancienne (séparées par une virgule)."
        )
