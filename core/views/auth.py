import time

import pyotp
import segno
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.db import transaction
from django.http import Http404
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .. import crypto
from ..forms import ChangePasswordForm, LoginForm, OTPForm, SetPasswordForm
from ..models import Invitation, User
from ..security import two_factor_paused_until
from ..utils import audit, client_ip, rate_limited, reset_rate


def _home_for(user):
    return "/dev/" if user.is_developer else "/espace/"


def login_view(request):
    if request.user.is_authenticated and request.session.get("otp_ok"):
        return redirect(_home_for(request.user))
    form = LoginForm(request.POST or None)
    if request.method == "POST":
        ip = client_ip(request)
        email = (request.POST.get("email") or "").lower()[:254]
        if rate_limited(f"login-ip:{ip}", 20, 900) or rate_limited(f"login-acc:{email}", 5, 900):
            audit(request, "login_throttled", email)
            messages.error(request, "Trop de tentatives. Réessayez dans 15 minutes.")
            return render(request, "auth/login.html", {"form": form}, status=429)
        if form.is_valid():
            user = authenticate(request, email=form.cleaned_data["email"].lower(), password=form.cleaned_data["password"])
            if user is not None and user.is_active:
                reset_rate(f"login-acc:{email}")
                login(request, user)  # régénère l'identifiant de session
                request.session["otp_ok"] = False
                if two_factor_paused_until():
                    request.session["otp_ok"] = True
                    audit(request, "login_ok_2fa_paused")
                    return redirect(_home_for(user))
                nxt = request.GET.get("next", "")
                if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
                    request.session["after_otp"] = nxt
                return redirect("auth:otp")
            audit(request, "login_failed", email)
            messages.error(request, "Adresse e-mail ou mot de passe incorrect.")
    return render(request, "auth/login.html", {"form": form})


def _check_totp(user, secret, code):
    """Vérifie le code (±30 s) et refuse la réutilisation d'un code déjà accepté."""
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):
        if step > user.totp_last_step and crypto_eq(totp.at(step * 30), code):
            return step
    return None


def crypto_eq(a, b):
    import hmac

    return hmac.compare_digest(str(a), str(b))


def otp_view(request):
    user = request.user
    if not user.is_authenticated:
        return redirect("auth:login")
    if request.session.get("otp_ok"):
        return redirect(_home_for(user))
    if two_factor_paused_until():
        request.session["otp_ok"] = True
        audit(request, "login_ok_2fa_paused")
        return redirect(_home_for(user))
    enrolling = not user.totp_confirmed
    if enrolling and not request.session.get("totp_pending"):
        request.session["totp_pending"] = crypto.encrypt(pyotp.random_base32())
    secret = crypto.decrypt(request.session["totp_pending"]) if enrolling else user.totp_secret

    form = OTPForm(request.POST or None)
    if request.method == "POST":
        if rate_limited(f"otp:{user.pk}", 6, 300):
            audit(request, "otp_throttled")
            logout(request)
            messages.error(request, "Trop de codes erronés. Reconnectez-vous dans 5 minutes.")
            return redirect("auth:login")
        if form.is_valid():
            step = _check_totp(user, secret, form.cleaned_data["code"])
            if step:
                if enrolling:
                    user.totp_secret = secret
                    user.totp_confirmed = True
                    request.session.pop("totp_pending", None)
                    audit(request, "otp_enrolled")
                user.totp_last_step = step
                user.last_login = timezone.now()
                user.save(update_fields=["totp_secret", "totp_confirmed", "totp_last_step", "last_login"])
                request.session.cycle_key()
                request.session["otp_ok"] = True
                reset_rate(f"otp:{user.pk}")
                audit(request, "login_ok")
                return redirect(request.session.pop("after_otp", None) or _home_for(user))
            form.add_error("code", "Code incorrect ou déjà utilisé.")

    ctx = {"form": form, "enrolling": enrolling}
    if enrolling:
        uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Sèmè Kids")
        ctx["qr_svg"] = segno.make(uri, error="m").svg_inline(scale=5, dark="#0b1b3f", light="#ffffff", border=2)
        ctx["secret_display"] = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    return render(request, "auth/otp.html", ctx)


@require_POST
def logout_view(request):
    if request.user.is_authenticated:
        audit(request, "logout")
    logout(request)
    return redirect("public:home")


def accept_invitation(request, token):
    ip = client_ip(request)
    if rate_limited(f"invite:{ip}", 20, 600):
        raise Http404
    inv = Invitation.objects.filter(token_hash=crypto.token_hash(token)).select_related("created_by").first()
    if inv is None or not inv.usable:
        return render(request, "auth/invite_invalid.html", status=404)
    principal = inv.kind in (Invitation.PRINCIPAL_ADMIN, Invitation.LEAD_DEV)
    kind = User.DEVELOPER if inv.kind in (Invitation.SUB_DEV, Invitation.LEAD_DEV) else User.ADMIN
    if principal and User.objects.filter(kind=kind, is_principal=True).exists():
        return render(request, "auth/invite_invalid.html", status=404)
    if request.user.is_authenticated:
        logout(request)

    initial = {"full_name": inv.full_name, "email": inv.email}
    form = SetPasswordForm(request.POST or None, initial=initial)
    if inv.email:
        form.fields["email"].disabled = True
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        with transaction.atomic():
            inv = Invitation.objects.select_for_update().get(pk=inv.pk)
            if not inv.usable:
                return render(request, "auth/invite_invalid.html", status=404)
            user = User.objects.create_user(
                email=inv.email or d["email"],
                password=d["password1"],
                full_name=d["full_name"],
                phone=d.get("phone", ""),
                kind=kind,
                is_principal=principal,
                roles=[] if principal else inv.roles,
                created_by=inv.created_by,
            )
            inv.used_at = timezone.now()
            inv.save(update_fields=["used_at"])
        audit(request, "account_created", f"{user.title} : {user.email}", actor=user)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        request.session["otp_ok"] = False
        if two_factor_paused_until():
            request.session["otp_ok"] = True
            return redirect(_home_for(user))
        return redirect("auth:otp")
    tpl = {
        Invitation.PRINCIPAL_ADMIN: "auth/register_admin.html",
        Invitation.LEAD_DEV: "auth/register_dev.html",
    }.get(inv.kind, "auth/invite.html")
    return render(request, tpl, {"form": form, "inv": inv})


def change_password(request):
    form = ChangePasswordForm(request.user, request.POST or None)
    if request.method == "POST" and form.is_valid():
        request.user.set_password(form.cleaned_data["password1"])
        request.user.save(update_fields=["password"])
        update_session_auth_hash(request, request.user)
        audit(request, "password_changed")
        messages.success(request, "Mot de passe modifié.")
        return redirect(request.path)
    base = "dev/base.html" if request.user.is_developer else "espace/base.html"
    return render(request, "auth/password.html", {"form": form, "base": base, "nav": "account"})
