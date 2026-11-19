import datetime

from core import crypto
from core.models import Registration
from core.qr import build_fragment, qr_url, verify_fragment


DATA = {"nom": "HOUNSOU", "prenom": "Marie", "parent_name": "Rosine", "parent_phone": "+2290197000000", "paroisse": "Akpakpa"}


def test_signature_roundtrip_and_tamper(db):
    f = build_fragment("ABCDEFGHJKMN", datetime.date(2027, 1, 1), DATA)
    assert verify_fragment("ABCDEFGHJKMN", f).ok
    # Le même code signé ne peut pas être recopié sur un autre identifiant
    assert not verify_fragment("ABCDEFGHJKMP", f).ok
    # Modifier le numéro des parents casse la signature
    p64, s64 = f.split(".")
    payload = crypto.b64u_decode(p64).decode().replace("+2290197000000", "+2290199999999")
    forged = crypto.b64u(payload.encode()) + "." + s64
    assert not verify_fragment("ABCDEFGHJKMN", forged).ok
    # Signature aléatoire / tronquée / format absurde
    assert not verify_fragment("ABCDEFGHJKMN", p64 + "." + crypto.b64u(b"\x00" * 64)).ok
    assert not verify_fragment("ABCDEFGHJKMN", p64 + ".abc").ok
    assert not verify_fragment("ABCDEFGHJKMN", "n'importe quoi").ok


def test_pipe_injection_cannot_shift_fields(db):
    evil = {**DATA, "prenom": "Marie|+2290100000000"}
    f = build_fragment("ABCDEFGHJKMN", datetime.date(2027, 1, 1), evil)
    d = verify_fragment("ABCDEFGHJKMN", f).data
    assert d["parent_phone"] == "+2290197000000"


def test_qr_url_fits_printable_qr(db):
    import segno

    long = {**DATA, "nom": "A" * 60, "prenom": "B" * 60, "parent_name": "C" * 80, "paroisse": "D" * 80,
            "parent_phone2": "+2290197000000", "charge_phone": "+2290197000000"}
    url = qr_url("ABCDEFGHJKMN", build_fragment("ABCDEFGHJKMN", datetime.date(2027, 1, 1), long))
    assert segno.make(url, error="m").version <= 20


def test_personal_data_is_encrypted_at_rest(registration):
    from django.db import connection

    with connection.cursor() as c:
        c.execute("SELECT nom, prenom, parent_phone, paroisse, qr_fragment FROM core_registration WHERE id=%s", [registration.pk])
        row = c.fetchone()
    for raw in row:
        assert raw.startswith("gAAAA")  # jeton Fernet
    assert "HOUNSOU" not in " ".join(row)
    assert Registration.objects.get(pk=registration.pk).nom == "HOUNSOU"


def test_tokens_are_stored_hashed(link_factory):
    link = link_factory()
    assert link.raw_token not in link.token_hash
    assert link.token_hash == crypto.token_hash(link.raw_token)


def test_reference_is_sequential_and_signed(link_factory):
    from core.qr import verify_fragment
    from core.views.public import _create_registration

    from .conftest import CHILD

    link = link_factory(quota=3)
    regs = [_create_registration(link, {**CHILD, "prenom": p, "parent_phone": "+2290197000000"}) for p in ("A", "B")]
    assert [r.ref_display for r in regs] == ["SK-0001", "SK-0002"]
    assert verify_fragment(regs[1].public_id, regs[1].qr_fragment).data["ref"] == "SK-0002"


def test_keys_can_be_derived_from_railway_secrets(settings):
    """Railway peut générer des secrets aléatoires (${{ secret(64) }}) : on en dérive des clés stables."""
    from core import crypto as c

    seed_f, seed_s = "f" * 20 + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "s" * 20 + "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210"
    settings.KIDLINK_FIELD_KEYS, settings.KIDLINK_SIGNING_KEY = seed_f, seed_s
    for f in (c._fernet, c._signing_key, c._pepper):
        f.cache_clear()
    try:
        token = c.encrypt("Marie")
        pub = c.public_key_spki_b64()
        sig = c.sign(b"bonjour")
        c._fernet.cache_clear(); c._signing_key.cache_clear()
        assert c.decrypt(token) == "Marie"  # même secret -> même clé après redémarrage
        assert c.public_key_spki_b64() == pub and c.verify(b"bonjour", sig)
        settings.KIDLINK_SIGNING_KEY = "trop-court"
        c._signing_key.cache_clear()
        import pytest
        from django.core.exceptions import ImproperlyConfigured

        with pytest.raises(ImproperlyConfigured):
            c._signing_key()
    finally:
        settings.KIDLINK_FIELD_KEYS = settings.KIDLINK_SIGNING_KEY = ""
        for f in (c._fernet, c._signing_key, c._pepper):
            f.cache_clear()


def test_signature_malleability_rejected(db):
    """(r, n - s) est mathématiquement valide : on l'interdit (signatures « low-S » uniquement)."""
    from core.crypto import P256_N

    f = build_fragment("ABCDEFGHJKMN", datetime.date(2027, 1, 1), DATA)
    p64, s64 = f.split(".")
    raw = crypto.b64u_decode(s64)
    r, s = raw[:32], int.from_bytes(raw[32:], "big")
    assert s <= P256_N // 2  # signature produite en forme canonique
    flipped = crypto.b64u(r + (P256_N - s).to_bytes(32, "big"))
    assert not verify_fragment("ABCDEFGHJKMN", p64 + "." + flipped).ok
