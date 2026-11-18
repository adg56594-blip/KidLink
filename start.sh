#!/bin/sh
# Démarrage Railway : base à jour + lien d'activation, puis serveur web.
set -e
python manage.py predeploy
exec gunicorn config.wsgi --bind "0.0.0.0:${PORT:-8000}" --workers 3 --timeout 60 --access-logfile -
