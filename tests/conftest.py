import time
from datetime import timedelta

import pyotp
import pytest
from django.core.cache import cache
from django.utils import timezone

from core import crypto
from core.models import Event, RegistrationLink, User
from core.views.public import _create_registration

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PWD = "Tres-Solide-Mot-2026!"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


def make_user(email, kind, principal=False, roles=None):
    return User.objects.create_user(
        email=email, password=PWD, full_name=email.split("@")[0], kind=kind, is_principal=principal,
        roles=roles or [], totp_secret=SECRET, totp_confirmed=True,
    )


@pytest.fixture
def lead_dev(db):
    return make_user("lead@t.bj", User.DEVELOPER, principal=True)


@pytest.fixture
def admin(db):
    return make_user("admin@t.bj", User.ADMIN, principal=True)


@pytest.fixture
def event(db, admin):
    today = timezone.localdate()
    return Event.objects.create(
        title="Pèlerinage test", location="Plage", starts_on=today + timedelta(days=10),
        ends_on=today + timedelta(days=12), price_per_child=1000, retention_days=30, created_by=admin,
    )


@pytest.fixture
def link_factory(db, event, admin):
    def make(quota=3, mode="hold", token=None):
        token = token or crypto.new_token(24)
        link = RegistrationLink.objects.create(
            event=event, label="Famille Test", payer_name="Payeur", quota=quota, amount_received=quota * 1000,
            token_hash=crypto.token_hash(token), token_hint=token[-4:], expires_at=timezone.now() + timedelta(days=3),
            created_by=admin, delivery_mode=mode,
        )
        link.raw_token = token
        return link

    return make


CHILD = {
    "nom": "Hounsou", "prenom": "Marie", "parent_name": "Rosine Hounsou", "parent_phone": "01 97 00 00 00",
    "parent_phone2": "", "paroisse": "Paroisse Akpakpa", "charge_name": "", "charge_phone": "",
}


@pytest.fixture
def registration(link_factory):
    link = link_factory()
    return _create_registration(link, {**CHILD, "nom": "HOUNSOU", "parent_phone": "+2290197000000"})


def staff_client(client, user):
    """Connexion complète : mot de passe + code TOTP (étape suivante garantie)."""
    client.post("/connexion/", {"email": user.email, "password": PWD})
    step = int(time.time()) // 30 + 1  # code de la période suivante (accepté, jamais encore utilisé)
    user.refresh_from_db()
    r = client.post("/connexion/code/", {"code": pyotp.TOTP(SECRET).at(step * 30)})
    assert r.status_code == 302, r.content[:400]
    return client
