"""Rôles et droits.

- Développeur principal : accès total, nomme les sous-développeurs.
- Sous-développeur : uniquement les rôles cochés par le développeur principal.
- Administrateur (le patron) : voit les gains, crée et envoie les liens après paiement,
  inscrit lui-même des enfants, voit les inscrits. Il n'a JAMAIS accès aux QR codes ni aux
  PDF : ce sont les développeurs qui génèrent et préparent les bracelets.
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

GAINS = "gains"
# Ce que l'administrateur peut faire (jamais « documents » = QR/PDF).
ADMIN_ROLES = {GAINS, "links", "registrations"}


def clean_roles(values, allowed):
    return sorted({v for v in values if v in allowed})
