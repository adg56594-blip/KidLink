"""Contenu des QR codes.

URL imprimée :  {PUBLIC_URL}/v/{public_id}#{payload_b64}.{signature_b64}

- Le fragment (#…) n'est jamais envoyé à un serveur par le navigateur : les
  informations restent entre le bracelet et le téléphone qui le scanne.
- Le payload contient le strict nécessaire pour joindre la famille hors ligne.
- La signature ECDSA lie le payload à l'identifiant : changer une seule lettre
  (ex. remplacer le numéro des parents) rend le bracelet « FALSIFIÉ ».
"""
from dataclasses import dataclass

from django.conf import settings

from . import crypto

# Version 1 : sans le nom du chargé. Version 2 : nom du chargé ajouté à la fin.
# Les deux restent valides : les bracelets déjà créés continuent de fonctionner.
FIELDS_BY_VERSION = {
    "1": ["expiry", "nom", "prenom", "parent_name", "parent_phone", "parent_phone2", "paroisse", "charge_phone", "ref"],
    "2": ["expiry", "nom", "prenom", "parent_name", "parent_phone", "parent_phone2", "paroisse", "charge_phone", "ref", "charge_name"],
}
VERSION = "2"
FIELDS = FIELDS_BY_VERSION[VERSION]
SIGN_PREFIX = "KL1"  # préfixe du message signé (inchangé ; la version est dans le contenu signé)


def _clean(v: str) -> str:
    return (v or "").replace("|", "/").replace("\n", " ").strip()


def signed_message(public_id: str, payload: str) -> bytes:
    return f"{SIGN_PREFIX}|{public_id}|{payload}".encode("utf-8")


def build_fragment(public_id: str, expiry, data: dict) -> str:
    values = [expiry.strftime("%Y%m%d")] + [_clean(data.get(k, "")) for k in FIELDS[1:]]
    payload = VERSION + "|" + "|".join(values)
    sig = crypto.sign(signed_message(public_id, payload))
    return crypto.b64u(payload.encode("utf-8")) + "." + crypto.b64u(sig)


def qr_url(public_id: str, fragment: str) -> str:
    return f"{settings.KIDLINK_PUBLIC_URL}/v/{public_id}#{fragment}"


@dataclass
class Decoded:
    ok: bool
    payload: str = ""
    data: dict | None = None


def verify_fragment(public_id: str, fragment: str) -> Decoded:
    try:
        p64, s64 = fragment.split(".", 1)
        payload = crypto.b64u_decode(p64).decode("utf-8")
        sig = crypto.b64u_decode(s64)
    except (ValueError, UnicodeDecodeError):
        return Decoded(False)
    if not crypto.verify(signed_message(public_id, payload), sig):
        return Decoded(False)
    parts = payload.split("|")
    fields = FIELDS_BY_VERSION.get(parts[0])
    if fields is None or len(parts) != len(fields) + 1:
        return Decoded(False)
    data = dict(zip(fields, parts[1:]))
    data.setdefault("charge_name", "")
    return Decoded(True, payload, data)
