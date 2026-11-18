"""Rôles et droits.

- Développeur principal : accès total, crée les sous-développeurs.
- Sous-développeur : uniquement les rôles cochés par le développeur principal.
- Administrateur principal : tous les rôles administrateur, seul à créer des sous-admins.
- Sous-administrateur : uniquement les rôles cochés par l'administrateur principal.

Un administrateur n'a JAMAIS accès aux QR codes ni aux PDF tant que les
développeurs ne les ont pas livrés.
"""

ADMIN_ROLES = {
    "events": "Gérer les événements",
    "links": "Créer et gérer les liens d'inscription",
    "registrations": "Voir la liste des inscrits",
    "documents": "Télécharger les PDF livrés",
    "purge": "Vider les données d'un événement terminé",
}

DEV_ROLES = {
    "deliveries": "Décider de l'envoi des PDF à l'administration",
    "dev_documents": "Télécharger tous les PDF des bracelets",
    "accounts": "Gérer les comptes administrateurs",
    "audit": "Consulter le journal de sécurité",
    "settings": "Modifier les réglages de la plateforme",
}

# Un sous-développeur peut aussi recevoir des droits de l'espace administration.
DEV_ASSIGNABLE = {**DEV_ROLES, **ADMIN_ROLES}


def clean_roles(values, allowed):
    return sorted({v for v in values if v in allowed})
