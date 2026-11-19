#!/bin/sh
# Démarrage Railway : base à jour + lien d'activation, puis serveur web.
set -e
python manage.py predeploy
exec gunicorn config.wsgi
