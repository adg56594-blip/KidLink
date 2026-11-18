from django.shortcuts import render


def forbidden(request, exception=None):
    return render(request, "public/error.html", {"code": 403, "title": "Accès refusé", "text": "Vous n'avez pas le droit d'ouvrir cette page."}, status=403)


def not_found(request, exception=None):
    return render(request, "public/error.html", {"code": 404, "title": "Page introuvable", "text": "Ce lien n'existe pas ou n'est plus valable."}, status=404)


def server_error(request):
    return render(request, "public/error.html", {"code": 500, "title": "Erreur", "text": "Un problème est survenu. Réessayez dans un instant."}, status=500)


def csrf_failure(request, reason=""):
    return render(request, "public/error.html", {"code": 403, "title": "Session expirée", "text": "Pour votre sécurité, rechargez la page puis réessayez."}, status=403)
