from django.shortcuts import render


def forbidden(request, exception=None):
    return render(request, "public/error.html", {"code": 403, "title": "Accès refusé", "text": "Vous n'avez pas le droit d'ouvrir cette page."}, status=403)


def not_found(request, exception=None):
    return render(request, "public/error.html", {"code": 404, "title": "Page introuvable", "text": "Ce lien n'existe pas ou n'est plus valable."}, status=404)


def server_error(request):
    """Ne dépend PAS de la base de données : doit fonctionner même si elle est indisponible."""
    from django.http import HttpResponseServerError
    from django.template import loader

    html = loader.get_template("public/error500.html").render({})
    return HttpResponseServerError(html)


# Champs qu'on peut remettre dans le formulaire après un jeton de sécurité expiré
# (jamais de mot de passe ni de code).
RETRY_FIELDS = {
    "/connexion/": ["email"],
    "/i/": ["nom", "prenom", "parent_name", "parent_phone", "parent_phone2", "paroisse", "charge_name", "charge_phone"],
}


# Adresses qui n'acceptent que des envois (pas de page à afficher).
POST_ONLY_SEGMENTS = ("/activer/", "/regenerer/", "/bracelet/", "/action/", "/annuler/", "/administrateur/inscription/", "/mot-de-passe/")


def csrf_failure(request, reason=""):
    """Jeton anti-falsification expiré ou absent (page restée ouverte, ré-affichée par le navigateur,
    lien ouvert depuis WhatsApp…). Au lieu d'une page d'erreur : on recharge le formulaire avec un
    jeton neuf, on remet ce qui avait été tapé, et on invite à réessayer. La protection reste entière :
    la demande d'origine n'est PAS exécutée."""
    import logging
    from urllib.parse import urlsplit

    from django.conf import settings
    from django.contrib import messages
    from django.http import HttpResponseRedirect
    from django.utils.http import url_has_allowed_host_and_scheme

    logging.getLogger("kidlink").warning("CSRF refusé sur %s : %s", request.path, reason)
    try:
        from ..utils import audit

        ua = request.META.get("HTTP_USER_AGENT", "")
        device = "iPhone" if "iPhone" in ua else ("Android" if "Android" in ua else "autre")
        inapp = " (navigateur WhatsApp)" if "WhatsApp" in ua or "FBAN" in ua else ""
        audit(request, "security_token_refreshed", f"{request.path} · {reason[:80]} · {device}{inapp}")
    except Exception:  # nosec B110
        pass
    path = request.path
    if path == "/deconnexion/" or any(seg in path for seg in POST_ONLY_SEGMENTS):
        # Bouton sans page à lui (ex. « Se déconnecter ») : retour sur la page d'où l'on vient.
        ref = request.META.get("HTTP_REFERER", "")
        ok = ref and url_has_allowed_host_and_scheme(ref, allowed_hosts={request.get_host()}, require_https=request.is_secure())
        path = (urlsplit(ref).path or "/") if ok else "/"
    retried = request.GET.get("rt") == "1"

    cookies_blocked = retried and settings.CSRF_COOKIE_NAME not in request.COOKIES
    if cookies_blocked or not url_has_allowed_host_and_scheme(path, allowed_hosts={request.get_host()}):
        # Après une actualisation, le cookie de sécurité n'est toujours pas renvoyé : cookies bloqués.
        return render(request, "public/error.html", {
            "code": 403, "title": "Cookies bloqués",
            "text": "Votre navigateur bloque les cookies de ce site, nécessaires à la connexion sécurisée. "
                    "Ouvrez le lien dans Safari ou Chrome (pas dans WhatsApp), ou autorisez les cookies, puis réessayez.",
        }, status=403)
    for prefix, fields in RETRY_FIELDS.items():
        if path.startswith(prefix):
            request.session["form_retry"] = {"path": path, "data": {f: request.POST.get(f, "")[:120] for f in fields}}
            break
    messages.warning(request, "Pour votre sécurité, la page vient d'être actualisée. Vérifiez puis appuyez à nouveau sur le bouton.")
    params = request.GET.copy()
    params["rt"] = "1"
    return HttpResponseRedirect(f"{path}?{params.urlencode()}")


def pop_retry(request):
    """Données à remettre dans le formulaire après une actualisation de sécurité (ou {})."""
    r = request.session.get("form_retry")
    if r and r.get("path") == request.path:
        request.session.pop("form_retry", None)
        return r.get("data") or {}
    return {}
