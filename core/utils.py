import re

from django.conf import settings
from django.core.cache import cache

from . import crypto


def client_ip(request) -> str:
    """IP réelle. On ne fait confiance à X-Forwarded-For que derrière N proxys déclarés."""
    n = settings.KIDLINK_TRUSTED_PROXIES
    if n > 0:
        chain = [p.strip() for p in request.META.get("HTTP_X_FORWARDED_FOR", "").split(",") if p.strip()]
        if len(chain) >= n:
            return chain[-n]
    return request.META.get("REMOTE_ADDR", "")


def rate_limited(key: str, limit: int, window: int) -> bool:
    """Vrai si la limite est dépassée. Compteur à fenêtre fixe dans le cache."""
    k = "rl:" + crypto.token_hash(key)[:40]
    if cache.add(k, 1, window):
        return False
    try:
        n = cache.incr(k)
    except ValueError:
        cache.set(k, 1, window)
        return False
    return n > limit


def rate_count(key: str) -> int:
    """Lit un compteur sans l'augmenter."""
    return cache.get("rl:" + crypto.token_hash(key)[:40]) or 0


def reset_rate(key: str):
    cache.delete("rl:" + crypto.token_hash(key)[:40])


PHONE_RE = re.compile(r"^\+?\d{8,15}$")


def normalize_phone(raw: str) -> str:
    """'01 97 00 00 00' -> '+2290197000000' ; '+234 803…' conservé. Renvoie '' si invalide."""
    if not raw:
        return ""
    s = re.sub(r"[\s.\-()/]", "", raw.strip())
    if s.startswith("00"):
        s = "+" + s[2:]
    if not s.startswith("+"):
        if len(s) in (8, 10):  # numéros béninois (ancien format à 8, nouveau à 10 chiffres)
            s = "+229" + s
        else:
            s = "+" + s
    return s if PHONE_RE.match(s) else ""


def pretty_phone(p: str) -> str:
    if p.startswith("+229") and len(p) in (12, 14):
        d = p[4:]
        return "+229 " + " ".join(d[i : i + 2] for i in range(0, len(d), 2))
    return p


def wa_number(p: str) -> str:
    return re.sub(r"\D", "", p or "")


def audit(request, action: str, detail: str = "", actor=None):
    from .models import AuditLog

    user = actor or (request.user if request and request.user.is_authenticated else None)
    AuditLog.objects.create(
        actor=user,
        actor_label=f"{user.full_name} <{user.email}>" if user else "",
        action=action,
        detail=detail[:300],
        ip_hash=crypto.anonymize_ip(client_ip(request)) if request else "",
    )
