"""Configuration gunicorn (lue automatiquement au démarrage)."""
import os

import gunicorn

gunicorn.SERVER = "web"  # ne pas annoncer le logiciel ni sa version
bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "3"))
timeout = 60
limit_request_line = 4094
limit_request_fields = 60
limit_request_field_size = 8190
accesslog = None  # les adresses /i/<jeton>/ ne doivent pas finir dans les journaux
errorlog = "-"
