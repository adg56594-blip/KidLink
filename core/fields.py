from django.db import models

from . import crypto


class EncryptedTextField(models.TextField):
    """Champ texte chiffré au repos. Impossible de filtrer dessus en SQL (voulu)."""

    def from_db_value(self, value, expression, connection):
        return crypto.decrypt(value) if value else ""

    def to_python(self, value):
        return value if value is not None else ""

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        return crypto.encrypt(value) if value else ""
