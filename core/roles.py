"""Rôles et droits.

- Développeur principal : accès total, nomme les sous-développeurs.
- Sous-développeur : uniquement les rôles cochés par le développeur principal.
- Administrateur : NE GÈRE RIEN. Il voit seulement la page « Les gains »
  (argent encaissé, nombre d'enfants) et contacte les développeurs par WhatsApp.
  Il ne voit aucune donnée d'enfant, aucun QR code, aucun PDF.
"""

DEV_ROLES = {
    "events": "Gérer les pèlerinages (dates, prix, affichage sur l'accueil)",
    "links": "Créer les liens d'inscription après un paiement",
    "registrations": "Voir les enfants inscrits et désactiver un bracelet perdu",
    "documents": "Télécharger les PDF des bracelets à imprimer",
    "purge": "Vider les données d'un pèlerinage terminé",
    "accounts": "Gérer le compte de l'administrateur",
    "audit": "Consulter le journal de sécurité",
    "settings": "Modifier les réglages (numéros affichés, texte du bracelet)",
}

# Le seul « rôle » de l'administrateur : regarder les gains.
GAINS = "gains"


def clean_roles(values, allowed):
    return sorted({v for v in values if v in allowed})
