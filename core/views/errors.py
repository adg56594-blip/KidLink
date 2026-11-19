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


def csrf_failure(request, reason=""):
    return render(request, "public/error.html", {"code": 403, "title": "Session expirée", "text": "Pour votre sécurité, rechargez la page puis réessayez."}, status=403)
