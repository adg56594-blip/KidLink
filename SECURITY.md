# Sécurité de Sèmè Kids

Ce document décrit les protections en place, les tests effectués (avec leurs résultats réels)
et les **risques résiduels connus**. Aucune application n'est invulnérable ; ce qui suit est
ce qui a été vérifié, rien de plus.

## Conditions du test (19 novembre 2026)

- Serveur identique à la production : `DEBUG` désactivé, HTTPS, gunicorn 3 processus,
  PostgreSQL 16, compteurs anti-abus partagés en base, clés fournies par l'environnement.
- Comptes de chaque rôle (développeur principal, sous-développeur, administrateur),
  double authentification active.
- Script : [`security/pentest.py`](security/pentest.py) (rejouable, voir en bas).

## Résultat de la campagne d'attaques : 52 vérifications, 0 faille

Campagne rejouée après la réorganisation des rôles (l'administrateur ne voit plus que « Les gains »,
les développeurs gèrent tout).

```
    [OK  ] Config · En-têtes de sécurité HTTP 
    [OK  ] Config · CSP sans 'unsafe-inline' ni 'unsafe-eval' — default-src 'self'; script-src 'self'; style-src 'self'; img
    [OK  ] Config · Bannière serveur masquée — web
    [OK  ] Config · Page 404 sans trace technique (DEBUG off) 
    [OK  ] Config · Injection d'en-tête Host refusée — 400
    [OK  ] Config · Fichiers sensibles inaccessibles (17 chemins) 
    [OK  ] Config · Méthodes HTTP dangereuses refusées 
    [OK  ] Config · robots.txt interdit l'indexation 
    [INFO] Config · Cookies : Secure + HttpOnly + SameSite — vérifié dans la catégorie Authentification
    [OK  ] Auth · 18 pages internes inaccessibles sans connexion 
    [OK  ] Auth · Mot de passe seul (sans code 2FA) insuffisant 
    [OK  ] Auth · Force brute du code 2FA bloquée (déconnexion après 6 essais) 
    [OK  ] Auth · Rejeu d'un code 2FA déjà utilisé refusé — [True, False]
    [OK  ] Auth · Force brute du mot de passe bloquée (429 après 5 essais) — [200, 200, 200, 200, 200, 429, 429]
    [OK  ] Auth · Usurpation X-Forwarded-For ne contourne pas le blocage — [429, 429, 429]
    [OK  ] Auth · Pas d'énumération des comptes (message + durée) — existant 114 ms / inconnu 122 ms, réponses identiques=True
    [OK  ] Auth · Fixation de session impossible (nouvel identifiant à la connexion) — 3zoni7
    [OK  ] Auth · Cookie de session Secure + HttpOnly + SameSite — {'secure': True, 'httponly': True, 'samesite': 'Lax'}
    [OK  ] Auth · Déconnexion forcée par simple lien (GET) impossible — 405
    [OK  ] Auth · Redirection ouverte après connexion impossible — /espace/
    [OK  ] CSRF · 6 actions refusées sans jeton CSRF / depuis un autre site 
    [OK  ] CSRF · Formulaire d'inscription public protégé par CSRF — 403
    [OK  ] CSRF · API de vérification : sans effet sensible (lecture seule, aucune donnée renvoyée) — {'status': 'valid', 'checked_at': '19/11/2026 à 13:42', 'event': 'Pèlerinage test'}
    [OK  ] Accès · Administrateur (admin@t.bj) : uniquement « Les gains » (23 tentatives) 
    [OK  ] Accès · Administrateur (sub@t.bj) : uniquement « Les gains » (23 tentatives) 
    [OK  ] Accès · Page « Les gains » : aucune donnée d'enfant ni de famille 
    [OK  ] Accès · Développeur principal : effacement possible à tout moment (formulaire affiché) 
    [OK  ] Accès · Identifiant inexistant -> 404 propre (pas d'erreur 500) 
    [OK  ] Accès · Sous-développeur limité à son rôle 
    [INFO] Injection · Formulaire public : charges hostiles acceptées sans erreur (10/10) 
    [OK  ] Injection · XSS stockée : aucune charge exécutable dans les pages (public + admin) 
    [OK  ] Injection · Injection de gabarit {{7*7}} non évaluée 
    [OK  ] Injection · Injection SQL dans la recherche sans effet (ORM paramétré) — 0.1s
    [OK  ] Injection · API de vérification robuste aux entrées malformées 
    [OK  ] Injection · Routes publiques refusent les identifiants malformés — 404/404
    [OK  ] Injection · Génération PDF avec noms hostiles sans plantage — 112593 octets
    [OK  ] Injection · Nom de fichier PDF assaini (pas d'injection d'en-tête) — attachment; filename="bracelets-pelerinage-test-famille-xss-li.pdf"
    [OK  ] Logique · Course : 30 envois simultanés sur un lien de 5 places — 5 acceptés, codes=[302, 403, 410]
    [OK  ] Logique · Références SK-xxxx uniques sous concurrence (vérif. base ci-dessous) 
    [OK  ] Logique · Quotas absurdes ou incohérents refusés (7 cas) 
    [OK  ] Logique · Devinette de liens d'inscription : rien trouvé (40 essais, 192 bits) 
    [OK  ] Logique · Invitation utilisée une seule fois même en simultané — [404, 404, 302, 404, 404, 404, 404, 404]
    [OK  ] QR · Bracelet authentique reconnu 
    [OK  ] QR · 8 falsifications détectées 
    [OK  ] QR · Signature transplantée sur un autre identifiant détectée 
    [OK  ] QR · Énumération d'identifiants : aucune information obtenue — {'forged'}
    [OK  ] QR · La page du bracelet ne contient aucune donnée (tout est dans le fragment local) 
    [OK  ] DoS · Corps de requête énorme refusé — 400
    [OK  ] DoS · Trop de champs de formulaire refusés — 400
    [OK  ] DoS · Mot de passe géant ne bloque pas le serveur — 200 en 0.13s
    [OK  ] DoS · Limitation de débit de l'API partagée entre les 3 processus — 59 acceptés puis 429
    [OK  ] DoS · En-têtes HTTP géants refusés — 431
```

Contrôles complémentaires :

| Contrôle | Résultat |
|---|---|
| Vidage complet de la base (`pg_dump`) : recherche des noms, numéros, paroisses en clair | **0 occurrence** — tout est chiffré (Fernet) |
| Mots de passe | Argon2id |
| Liens d'inscription, invitations | seule une empreinte HMAC-SHA256 est stockée |
| Secrets 2FA | chiffrés en base |
| `pytest` (66 tests unitaires et d'intégration) | 66 réussis |
| `bandit` (analyse statique Python) | 0 problème |
| `pip-audit` (vulnérabilités connues des dépendances) | 0 vulnérabilité |
| `manage.py check --deploy` | 0 avertissement |
| `semgrep` | **non exécuté** (règles non téléchargeables depuis l'environnement de test) |

## Failles trouvées pendant l'audit, puis corrigées

| Problème | Gravité | Correction |
|---|---|---|
| Blocage volontaire du compte de l'administrateur : 5 mauvais mots de passe sur son e-mail, depuis n'importe où, bloquaient sa connexion 15 min | Moyenne (déni de service ciblé) | Blocage par couple (compte, IP) + plafond global plus haut par compte |
| Compteurs anti-abus non partagés entre les processus (×3 essais) et remis à zéro à chaque redémarrage | Moyenne | Compteurs en base (ou Redis) partagés et persistants |
| Méthode `TRACE`/`PUT`/`DELETE` acceptée sur certaines pages | Faible (pas d'écho de la requête) | Seules `GET`, `HEAD`, `POST` sont acceptées partout |
| Page d'erreur 500 dépendante de la base : si la base tombe, réponse brute sans en-têtes de sécurité | Faible | Page 500 statique, sans accès à la base |
| Connexions à la base inutilisables après une coupure | Faible (disponibilité) | `CONN_HEALTH_CHECKS` |
| Bannière du serveur web (nom et version) | Info | Masquée |
| Adresses `/i/<jeton>/` écrites dans le journal d'accès | Faible | Journal d'accès gunicorn désactivé |
| Malléabilité ECDSA : (r, n−s) était accepté par la vérification **hors ligne** (aucune donnée modifiable, rejeté en ligne) | Faible | Signatures « low-S » imposées à la création, côté serveur et dans le téléphone |

## Risques résiduels connus (à connaître, assumés ou à décider)

1. **Les informations du bracelet sont lisibles par qui scanne le bracelet.** C'est le principe
   même du système (permettre d'appeler la famille, même sans internet) : nom de l'enfant,
   paroisse, nom et numéro du parent. Quelqu'un qui a l'enfant devant lui peut donc obtenir le
   numéro des parents (risque d'arnaque du type « votre enfant est avec moi »). Atténuations :
   rien d'autre n'est exposé, les données sont effacées après l'événement, et l'on peut
   sensibiliser les parents. Le supprimer imposerait de renoncer au fonctionnement hors ligne.
2. **Adresse IP derrière Railway.** Le blocage anti-force-brute fait confiance au dernier élément
   de `X-Forwarded-For` ajouté par le proxy de Railway. À confirmer en production
   (sur ce banc de test, l'usurpation de cet en-tête est sans effet).
3. **Hameçonnage.** Un faux site imitant la page de connexion peut voler mot de passe *et* code
   à 6 chiffres s'ils sont saisis aussitôt. Toujours vérifier l'adresse du site.
4. **Accès au projet Railway = accès total** (variables, clés, base). Protéger ce compte par
   une double authentification forte. La variable `KIDLINK_2FA_PAUSE_UNTIL` (pause de la 2FA,
   7 jours maximum) ne doit servir qu'aux tests.
5. **Perte de la clé 2FA du développeur principal** : pas de récupération automatique prévue.
6. **Journal des scans** : un attaquant disposant de nombreuses adresses IP peut le faire grossir
   (limité à 60 requêtes par minute et par IP).

## Rejouer les tests

```bash
pip install -r requirements-dev.txt requests
pytest
bandit -r core config
pip-audit -r requirements.txt
# Campagne d'attaques : serveur HTTPS de test sur https://127.0.0.1:8443 + base PostgreSQL « kidlink »
python security/pentest.py
```

Ne lancez jamais `security/pentest.py` contre le site de production : il crée des comptes,
remet à zéro les compteurs anti-abus de la base locale et envoie des centaines de requêtes.
