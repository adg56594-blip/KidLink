"""Met les signatures déjà stockées en forme canonique « low-S » (s <= n/2).
Le contenu signé ne change pas ; seule la forme de la signature est normalisée."""
import base64

from django.db import migrations

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def normalize(apps, schema_editor):
    from core import crypto

    Registration = apps.get_model("core", "Registration")
    for reg in Registration.objects.all().only("id", "qr_fragment"):
        frag = reg.qr_fragment  # le champ chiffré se déchiffre tout seul
        if "." not in frag:
            continue
        p64, s64 = frag.split(".", 1)
        raw = crypto.b64u_decode(s64)
        s = int.from_bytes(raw[32:], "big")
        if len(raw) == 64 and s > N // 2:
            fixed = p64 + "." + crypto.b64u(raw[:32] + (N - s).to_bytes(32, "big"))
            Registration.objects.filter(pk=reg.pk).update(qr_fragment=fixed)  # rechiffré par le champ


class Migration(migrations.Migration):
    dependencies = [("core", "0004_roles_simplifies")]
    operations = [migrations.RunPython(normalize, migrations.RunPython.noop)]
