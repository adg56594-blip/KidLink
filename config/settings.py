"""Réglages Django de Sèmè Kids.

Tout ce qui est secret ou dépend de l'hébergement se lit dans des variables
d'environnement (voir .env.example). En production (DEBUG désactivé), l'absence
d'une clé obligatoire empêche le démarrage : on préfère planter que tourner
sans protection.
"""
import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None):
    return os.environ.get(name, default)


def env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on", "oui"}


TESTING = "pytest" in sys.modules or (len(sys.argv) > 1 and sys.argv[1] == "test")
BUILD_PHASE = len(sys.argv) > 1 and sys.argv[1] == "collectstatic"  # construction : aucun secret requis
DEBUG = env_bool("DJANGO_DEBUG", False)
DEV_MODE = DEBUG or TESTING  # autorise des clés locales générées automatiquement

SECRET_KEY = env("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if not DEV_MODE and not BUILD_PHASE:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY est obligatoire en production.")
    SECRET_KEY = "dev-only-insecure-key-never-use-in-production-" + "x" * 20

RAILWAY_DOMAIN = env("RAILWAY_PUBLIC_DOMAIN", "")
ALLOWED_HOSTS = [h.strip() for h in env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]
if RAILWAY_DOMAIN:
    ALLOWED_HOSTS.append(RAILWAY_DOMAIN)
    ALLOWED_HOSTS.append("healthcheck.railway.app")
if TESTING:
    ALLOWED_HOSTS += ["testserver"]
CSRF_TRUSTED_ORIGINS = [o.strip() for o in env("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()]
if RAILWAY_DOMAIN:
    CSRF_TRUSTED_ORIGINS.append(f"https://{RAILWAY_DOMAIN}")

# Adresse publique utilisée dans les QR codes (sans barre finale).
KIDLINK_PUBLIC_URL = env("KIDLINK_PUBLIC_URL", f"https://{RAILWAY_DOMAIN}" if RAILWAY_DOMAIN else "http://localhost:8000").rstrip("/")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "core.security.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "core.security.StaffAreaMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.site",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

if env("DATABASE_URL"):
    from urllib.parse import unquote, urlparse

    _u = urlparse(env("DATABASE_URL"))
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _u.path.lstrip("/"),
            "USER": unquote(_u.username or ""),
            "PASSWORD": unquote(_u.password or ""),
            "HOST": _u.hostname,
            "PORT": str(_u.port or 5432),
            "CONN_MAX_AGE": 60,
        }
    }
elif env("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB"),
            "USER": env("POSTGRES_USER", ""),
            "PASSWORD": env("POSTGRES_PASSWORD", ""),
            "HOST": env("POSTGRES_HOST", "localhost"),
            "PORT": env("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 60,
            "OPTIONS": {"sslmode": env("POSTGRES_SSLMODE", "prefer")},
        }
    }
else:
    if not DEV_MODE and not BUILD_PHASE:
        # Sur Railway, le disque est effacé à chaque déploiement : SQLite perdrait tout.
        raise ImproperlyConfigured("DATABASE_URL (PostgreSQL) est obligatoire en production.")
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

if env("REDIS_URL"):
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": env("REDIS_URL")}}
else:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "kidlink"}}

AUTH_USER_MODEL = "core.User"
LOGIN_URL = "auth:login"

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
if TESTING:
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # tests rapides uniquement

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "fr"
TIME_ZONE = "Africa/Porto-Novo"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
        if DEV_MODE
        else "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATA_UPLOAD_MAX_MEMORY_SIZE = 256 * 1024  # aucun envoi de fichier n'est prévu
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200

# ---------- Sessions & cookies ----------
SESSION_COOKIE_AGE = 8 * 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_NAME = "kl_session"
CSRF_COOKIE_NAME = "kl_csrf"

# ---------- HTTPS (production) ----------
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"  # aucun lien (jeton) ne fuit vers un site extérieur
CSRF_FAILURE_VIEW = "core.views.errors.csrf_failure"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
if not DEV_MODE:
    SECURE_SSL_REDIRECT = env_bool("DJANGO_SSL_REDIRECT", True)
    SECURE_REDIRECT_EXEMPT = [r"^healthz/$"]
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 63072000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    if env_bool("DJANGO_BEHIND_PROXY", bool(RAILWAY_DOMAIN)):
        SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Nombre de proxys de confiance devant l'application (pour lire la vraie IP).
KIDLINK_TRUSTED_PROXIES = int(env("KIDLINK_TRUSTED_PROXIES", "1" if RAILWAY_DOMAIN else "0"))

# ---------- Clés cryptographiques ----------
# KIDLINK_FIELD_KEYS : une ou plusieurs clés Fernet séparées par des virgules
#   (la première chiffre, toutes déchiffrent -> rotation possible).
# KIDLINK_SIGNING_KEY : clé privée ECDSA P-256 au format PEM (signature des QR).
KIDLINK_KEYS_DIR = BASE_DIR / ".keys"
KIDLINK_FIELD_KEYS = env("KIDLINK_FIELD_KEYS", "")
KIDLINK_SIGNING_KEY = env("KIDLINK_SIGNING_KEY", "").replace("\\n", "\n")
if not DEV_MODE and not BUILD_PHASE and (not KIDLINK_FIELD_KEYS or not KIDLINK_SIGNING_KEY):
    raise ImproperlyConfigured(
        "KIDLINK_FIELD_KEYS et KIDLINK_SIGNING_KEY sont obligatoires en production "
        "(python manage.py generate_keys)."
    )

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "django.security": {"handlers": ["console"], "level": "WARNING"},
        "kidlink": {"handlers": ["console"], "level": "INFO"},
    },
}
