from datetime import datetime, timedelta
from functools import wraps

from django.conf import settings
from django.utils import timezone

from django.contrib.auth import logout
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseNotAllowed
from django.shortcuts import redirect

CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "font-src 'self'",
        "connect-src 'self'",
        "media-src 'self' blob:",
        "worker-src 'self'",
        "manifest-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

ALLOWED_METHODS = {"GET", "HEAD", "POST"}  # TRACE, PUT, DELETE, OPTIONS… : refusés partout
STAFF_PREFIXES = ("/espace/", "/dev/")
PRIVATE_PREFIXES = STAFF_PREFIXES + ("/i/", "/connexion", "/invitation/", "/inscription-administrateur/")


MAX_2FA_PAUSE = timedelta(days=7)


def two_factor_paused_until():
    """Date de fin de la pause 2FA si elle est valide et en cours, sinon None.
    Une date absurde (passée, illisible ou à plus de 7 jours) est ignorée : la 2FA reste active."""
    raw = settings.KIDLINK_2FA_PAUSE_UNTIL
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            until = timezone.make_aware(datetime.strptime(raw, fmt))
            break
        except ValueError:
            continue
    else:
        return None
    if fmt == "%Y-%m-%d":
        until += timedelta(days=1)  # jusqu'à la fin de la journée indiquée
    now = timezone.now()
    if now < until <= now + MAX_2FA_PAUSE:
        return until
    return None


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method not in ALLOWED_METHODS:
            response = HttpResponseNotAllowed(sorted(ALLOWED_METHODS))
        else:
            response = self.get_response(request)
        response.setdefault("Content-Security-Policy", CSP)
        response.setdefault("Permissions-Policy", "camera=(self), geolocation=(self), microphone=(), payment=(), usb=()")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.setdefault("X-Robots-Tag", "noindex, nofollow")
        if request.path.startswith(PRIVATE_PREFIXES):
            # Jamais de cache (navigateur, proxy) pour les pages contenant des données.
            response["Cache-Control"] = "no-store, private"
        return response


class StaffAreaMiddleware:
    """Les espaces /espace/ et /dev/ exigent un compte actif ET la double authentification."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if path.startswith(STAFF_PREFIXES):
            user = request.user
            if not user.is_authenticated:
                return redirect(f"/connexion/?next={path}")
            if not user.is_active:
                logout(request)
                return redirect("/connexion/")
            if not request.session.get("otp_ok"):
                return redirect("auth:otp")
            if path.startswith("/dev/") and not user.is_developer:
                raise PermissionDenied
        return self.get_response(request)


def role_required(*roles):
    """Accès si l'utilisateur possède AU MOINS un des rôles demandés."""

    def deco(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not any(request.user.has_role(r) for r in roles):
                raise PermissionDenied
            return view(request, *args, **kwargs)

        return wrapped

    return deco


def principal_admin_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_principal_admin:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped


def lead_dev_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_lead_dev:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped
