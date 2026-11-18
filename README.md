# Sèmè Kids — Christianisme Céleste

Le bracelet qui ramène l'enfant à sa famille. Pendant les pèlerinages de l'Église du
Christianisme Céleste, chaque enfant porte un bracelet avec un QR code. Si l'enfant se perd,
n'importe qui scanne le bracelet et appelle directement la famille, **même sans internet**.

Application web Django, installable sur téléphone (PWA), sans paiement en ligne :
l'administration encaisse elle-même, puis génère un lien d'inscription.

## Fonctionnement

1. **Paiement** : la famille ou le chargé de paroisse paie l'administration (espèces, Mobile Money…).
2. **Lien** : l'administrateur crée un lien pour le nombre exact d'enfants payés. Il saisit le nombre deux fois, le montant est contrôlé, et il doit cocher une confirmation. Le lien est ensuite envoyé par WhatsApp.
3. **Inscription** : la famille remplit une fiche courte par enfant : nom, prénom, parent, numéro, paroisse. Le chargé est facultatif et il n'y a pas de photo. Pour l'enfant suivant, la famille est déjà pré-remplie. Le lien se ferme tout seul une fois le quota atteint.
4. **QR et PDF** : le QR code signé est généré automatiquement. Le PDF d'impression (A4, 20 bracelets par page, QR de 40 mm, nom en dessous) n'est visible **ni par le client ni par l'administrateur** tant que les développeurs ne l'ont pas livré. Ils choisissent pour chaque lot : immédiat, différé de X heures, programmé, ou retenu.
5. **Scan** : un passant scanne le bracelet. La page affiche le nom de l'enfant et un gros bouton « Appeler la famille », plus WhatsApp avec sa position. La signature est vérifiée **dans le téléphone**, puis confirmée en ligne si le réseau est disponible.
6. **Effacement** : après la fin de l'événement et la durée de conservation choisie, l'administrateur vide les données. Une commande nocturne sert de filet de sécurité.

## Rôles

| Compte | Ce qu'il peut faire |
|---|---|
| Développeur principal | Tout. Crée les sous-développeurs, génère la page d'inscription de l'administrateur principal, décide de la livraison des PDF. |
| Sous-développeur | Uniquement les droits cochés : livraisons, PDF, comptes, journal, réglages, et éventuellement des droits d'administration. |
| Administrateur principal | Inscrit via une page spéciale à usage unique. Gère les événements, les liens, les inscrits, les PDF livrés et les purges. **Seul** à créer des sous-administrateurs. |
| Sous-administrateur | Uniquement les droits cochés par l'administrateur principal. |

## Sécurité

- **Bracelets infalsifiables** : chaque QR est signé en ECDSA P-256. Modifier un seul caractère (par exemple le numéro des parents) affiche « Bracelet FALSIFIÉ », même hors ligne. Le scanner intégré signale aussi les QR qui imitent Sèmè Kids depuis un autre site. Une horloge en direct et un sceau animé rendent une capture d'écran figée facile à repérer.
- **Confidentialité du scan** : les données de l'enfant sont dans le fragment `#…` de l'adresse, que le navigateur n'envoie jamais au serveur. L'API de vérification ne renvoie **aucune** donnée personnelle, seulement l'état du bracelet.
- **Chiffrement au repos** : noms, numéros, paroisse et QR sont chiffrés en base (Fernet, avec rotation de clés possible). Les liens et invitations ne sont stockés que sous forme d'empreinte HMAC.
- **Comptes** :
  - mots de passe Argon2 de 12 caractères minimum ;
  - **double authentification TOTP obligatoire**, sans réutilisation possible d'un code ;
  - verrouillage après 5 échecs ;
  - sessions de 8 h, renouvelées à la connexion.
- **Contrôle d'accès** : vérifié côté serveur sur chaque vue. Un administrateur ne peut ni ouvrir la console développeur ni télécharger un PDF non livré.
- **En-têtes et navigateur** :
  - CSP stricte (aucun script ni style en ligne), HSTS, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` ;
  - `no-store` sur les pages privées ;
  - aucune ressource externe (polices et bibliothèques hébergées sur place).
- **Anti-abus** :
  - limitation de débit (connexion, 2FA, API de scan, liens invalides) ;
  - verrou SQL sur le quota, pour que deux envois simultanés ne puissent pas le dépasser ;
  - les tentatives sur un lien invalide sont comptées, l'usage normal ne l'est pas : un chargé qui inscrit 50 enfants n'est jamais bloqué.
- **Journal de sécurité** : chaque action sensible est tracée (connexions, liens, téléchargements, purges…) avec une IP anonymisée.

## Installation (développement)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export DJANGO_DEBUG=1
python manage.py migrate
python manage.py create_developer --email vous@exemple.com --name "Votre nom"
python manage.py runserver
```

En développement, les clés sont créées automatiquement dans `.keys/` (ignoré par git).
Connectez-vous sur `/connexion/`, configurez la 2FA, puis dans **Administrateurs** générez
la page d'inscription de l'administrateur principal.

## Tests et audit

```bash
pytest                                    # 57 tests : crypto, accès, quotas, falsification, purge…
bandit -r core config                     # analyse statique de sécurité
pip-audit -r requirements.txt             # vulnérabilités connues des dépendances
python manage.py check --deploy           # avec les variables de production
```

## Production

1. Générez les clés (**une seule fois**, à garder dans un coffre-fort) : `python manage.py generate_keys`.
2. Renseignez les variables de `.env.example` : clés, `KIDLINK_PUBLIC_URL` en **https**, PostgreSQL, Redis (conseillé pour la limitation de débit avec plusieurs processus).
3. Lancez `python manage.py migrate` et `python manage.py collectstatic`, puis `gunicorn config.wsgi` derrière Nginx ou Caddy en HTTPS.
4. Ajoutez une tâche cron chaque nuit : `python manage.py purge_expired --grace 15`.

**Attention** : changer `KIDLINK_SIGNING_KEY` rend invalides tous les bracelets déjà imprimés.
Changer le domaine de `KIDLINK_PUBLIC_URL` a le même effet sur les QR existants.

## Déploiement sur Railway

Railway redéploie automatiquement à chaque commit sur la branche qu'il surveille (souvent `main`).
Le fichier `railway.json` s'occupe de tout : `collectstatic` pendant la construction, `migrate` avant le démarrage, puis gunicorn.
Le contrôle de santé `/healthz/` empêche une version cassée de remplacer celle qui tourne.

À faire **une seule fois** dans le projet Railway, avant de fusionner sur `main` :

1. **+ New → Database → PostgreSQL**, puis reliez la variable `DATABASE_URL` au service web.
2. Dans le service web, onglet **Variables**, ajoutez :
   - `DJANGO_SECRET_KEY`, `KIDLINK_FIELD_KEYS` et `KIDLINK_SIGNING_KEY`, générées en local avec `python manage.py generate_keys` ;
   - `KIDLINK_PUBLIC_URL`, seulement si vous utilisez un domaine personnalisé (sinon le domaine Railway est pris automatiquement) ;
   - `DJANGO_ALLOWED_HOSTS`, avec ce même domaine personnalisé s'il y en a un.
3. Après le premier déploiement, créez le développeur principal : `railway run python manage.py create_developer --email … --name …`.
4. Ajoutez une tâche cron Railway pour la purge nocturne : `python manage.py purge_expired --grace 15`.

## Contacts

- Administration (appel et WhatsApp) : +229 98 18 47 59
- Développeur (WhatsApp) : +229 67 32 43 61

Ces numéros se modifient dans **Console → Réglages**.
