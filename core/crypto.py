"""Cryptographie de Sèmè Kids.

1. Chiffrement des données personnelles en base (Fernet = AES-128-CBC + HMAC-SHA256).
   Une fuite de la base seule ne révèle ni noms ni numéros.
2. Signature des QR codes (ECDSA P-256 / SHA-256). Seul le serveur possède la clé
   privée ; la clé publique est livrée aux téléphones, qui vérifient l'authenticité
   d'un bracelet même sans connexion internet.
"""
import base64
import hashlib
import hmac
import secrets
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------- clés locales
def _dev_key_file(name: str, factory) -> str:
    """En développement/tests uniquement : clé générée et gardée dans .keys/."""
    if not settings.DEV_MODE:
        raise ImproperlyConfigured(f"Clé {name} absente.")
    d = settings.KIDLINK_KEYS_DIR
    d.mkdir(mode=0o700, exist_ok=True)
    path = d / name
    if not path.exists():
        path.write_text(factory())
        path.chmod(0o600)
    return path.read_text()


def new_field_key() -> str:
    return Fernet.generate_key().decode()


def new_signing_key_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


# ---------------------------------------------------------------- chiffrement
@lru_cache(maxsize=1)
def _fernet() -> MultiFernet:
    raw = settings.KIDLINK_FIELD_KEYS or _dev_key_file("field.key", new_field_key)
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    return MultiFernet([Fernet(_as_fernet_key(k)) for k in keys])


MIN_SEED = 32


def _as_fernet_key(k: str) -> bytes:
    """Accepte une vraie clé Fernet, ou une longue phrase secrète aléatoire (ex. générée
    par Railway avec ${{ secret(64) }}) dont on dérive une clé de 256 bits (HKDF-SHA256)."""
    try:
        if len(base64.urlsafe_b64decode(k.encode())) == 32:
            return k.encode()
    except (ValueError, TypeError):
        pass
    if len(k) < MIN_SEED:
        raise ImproperlyConfigured("KIDLINK_FIELD_KEYS : secret trop court (32 caractères minimum).")
    return base64.urlsafe_b64encode(_hkdf(k, b"kidlink-field-key-v1"))


def _hkdf(seed: str, info: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"kidlink", info=info).derive(seed.encode("utf-8"))


def encrypt(value: str) -> str:
    if value in (None, ""):
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:  # clé erronée ou donnée altérée : on refuse de deviner
        raise ValueError("Donnée chiffrée illisible") from exc


@lru_cache(maxsize=1)
def _pepper() -> bytes:
    return hashlib.sha256(b"kidlink-pepper:" + settings.SECRET_KEY.encode()).digest()


def token_hash(token: str) -> str:
    """Empreinte d'un jeton (liens, invitations). Seule l'empreinte est stockée."""
    return hmac.new(_pepper(), token.encode("utf-8"), hashlib.sha256).hexdigest()


def anonymize_ip(ip: str) -> str:
    return hmac.new(_pepper(), (ip or "").encode(), hashlib.sha256).hexdigest()[:16]


def new_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


# ---------------------------------------------------------------- signature
@lru_cache(maxsize=1)
def _signing_key() -> ec.EllipticCurvePrivateKey:
    pem = settings.KIDLINK_SIGNING_KEY or _dev_key_file("signing.pem", new_signing_key_pem)
    if "BEGIN" not in pem:
        # Phrase secrète aléatoire -> clé P-256 déterministe (toujours la même pour la même phrase).
        if len(pem.strip()) < MIN_SEED:
            raise ImproperlyConfigured("KIDLINK_SIGNING_KEY : secret trop court (32 caractères minimum).")
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        scalar = int.from_bytes(_hkdf(pem.strip(), b"kidlink-signing-key-v1") + _hkdf(pem.strip(), b"kidlink-signing-key-v1b"), "big") % (order - 1) + 1
        return ec.derive_private_key(scalar, ec.SECP256R1())
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ImproperlyConfigured("KIDLINK_SIGNING_KEY doit être une clé ECDSA P-256.")
    return key


def public_key_spki_b64() -> str:
    """Clé publique (SPKI DER, base64 standard) pour WebCrypto côté navigateur."""
    der = _signing_key().public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def public_key_fingerprint() -> str:
    return hashlib.sha256(public_key_spki_b64().encode()).hexdigest()[:16]


# Ordre de la courbe P-256. On impose des signatures « low-S » (s <= n/2) : sinon (r, n - s)
# serait une seconde signature valide du même contenu (malléabilité ECDSA).
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def sign(message: bytes) -> bytes:
    der = _signing_key().sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    if s > P256_N // 2:
        s = P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")  # format brut P1363 (WebCrypto)


def verify(message: bytes, raw_sig: bytes) -> bool:
    if len(raw_sig) != 64 or int.from_bytes(raw_sig[32:], "big") > P256_N // 2:
        return False
    der = encode_dss_signature(int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big"))
    try:
        _signing_key().public_key().verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
