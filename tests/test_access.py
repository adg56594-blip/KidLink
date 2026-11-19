"""Contrôle d'accès : qui peut voir / faire quoi."""
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from core import crypto
from core.models import AuditLog, Invitation, Registration, RegistrationLink, User

from .conftest import PWD, make_user, staff_client

ESPACE = ["/espace/", "/espace/evenements/", "/espace/liens/", "/espace/documents/", "/espace/equipe/", "/espace/compte/"]
DEV = ["/dev/", "/dev/livraisons/", "/dev/comptes/", "/dev/equipe/", "/dev/journal/", "/dev/reglages/"]


@pytest.mark.parametrize("url", ESPACE + DEV)
def test_anonymous_redirected_to_login(client, db, url):
    r = client.get(url)
    assert r.status_code == 302 and r["Location"].startswith("/connexion/")


def test_password_alone_is_not_enough(client, admin):
    client.post("/connexion/", {"email": admin.email, "password": PWD})
    r = client.get("/espace/")
    assert r.status_code == 302 and "/connexion/code/" in r["Location"]


def test_wrong_password_and_lockout(client, admin):
    for _ in range(5):
        client.post("/connexion/", {"email": admin.email, "password": "mauvais"})
    r = client.post("/connexion/", {"email": admin.email, "password": PWD})
    assert r.status_code == 429  # compte verrouillé 15 min, même avec le bon mot de passe
    assert AuditLog.objects.filter(action="login_failed").count() == 5


def test_totp_code_cannot_be_replayed(admin):
    import time

    import pyotp

    from .conftest import SECRET

    step = int(time.time()) // 30 + 1
    code = pyotp.TOTP(SECRET).at(step * 30)
    c1 = Client()
    c1.post("/connexion/", {"email": admin.email, "password": PWD})
    assert c1.post("/connexion/code/", {"code": code}).status_code == 302
    c2 = Client()
    c2.post("/connexion/", {"email": admin.email, "password": PWD})
    r = c2.post("/connexion/code/", {"code": code})
    assert r.status_code == 200  # refusé : code déjà utilisé
    assert c2.get("/espace/").status_code == 302


def test_open_redirect_blocked(client, admin):
    client.post("/connexion/?next=https://evil.example/", {"email": admin.email, "password": PWD})
    assert "after_otp" not in client.session


def test_admin_cannot_enter_dev_console(client, admin):
    staff_client(client, admin)
    for url in DEV:
        assert client.get(url).status_code == 403, url


def test_admin_cannot_download_unreleased_pdf(client, admin, registration):
    staff_client(client, admin)
    link = registration.link
    assert link.delivery_mode == "hold"
    assert client.get(f"/espace/documents/{link.pk}/pdf/").status_code == 403
    page = client.get("/espace/documents/").content.decode()
    assert f"/espace/documents/{link.pk}/pdf/" not in page
    # La page d'un lien ne révèle jamais le QR
    body = client.get(f"/espace/liens/{link.pk}/").content.decode()
    assert registration.qr_fragment not in body and registration.public_id not in body


def test_released_pdf_downloadable_by_admin(client, admin, registration):
    link = registration.link
    link.delivery_mode = "immediate"
    link.save()
    staff_client(client, admin)
    r = client.get(f"/espace/documents/{link.pk}/pdf/")
    assert r.status_code == 200 and r["Content-Type"] == "application/pdf" and r.content.startswith(b"%PDF")


def test_delayed_and_scheduled_delivery(registration):
    link = registration.link
    link.last_registration_at = timezone.now()
    link.delivery_mode = "delayed"
    link.delivery_delay_hours = 2
    assert not link.is_released
    link.last_registration_at = timezone.now() - timedelta(hours=3)
    assert link.is_released
    link.delivery_mode = "scheduled"
    link.delivery_scheduled_at = timezone.now() + timedelta(days=1)
    assert not link.is_released
    link.delivery_scheduled_at = timezone.now() - timedelta(seconds=1)
    assert link.is_released


def test_dev_controls_delivery(client, lead_dev, registration):
    staff_client(client, lead_dev)
    link = registration.link
    assert client.get(f"/dev/livraisons/{link.pk}/pdf/").status_code == 200
    client.post(f"/dev/livraisons/{link.pk}/", {"action": "save", "mode": "delayed", "delay_hours": "5"})
    link.refresh_from_db()
    assert link.delivery_mode == "delayed" and link.delivery_delay_hours == 5
    client.post(f"/dev/livraisons/{link.pk}/", {"action": "now"})
    link.refresh_from_db()
    assert link.delivery_mode == "immediate" and link.is_released


def test_sub_admin_limited_to_roles(client, admin, registration):
    sub = make_user("sub@t.bj", User.ADMIN, roles=["links"])
    staff_client(client, sub)
    assert client.get("/espace/liens/nouveau/").status_code == 200
    assert client.get("/espace/evenements/nouveau/").status_code == 403
    assert client.get("/espace/equipe/").status_code == 403
    assert client.get("/espace/documents/").status_code == 403
    # sans le rôle « inscriptions », la liste des enfants n'apparaît pas
    body = client.get(f"/espace/liens/{registration.link.pk}/").content.decode()
    assert "HOUNSOU" not in body
    assert client.post(f"/espace/bracelets/{registration.pk}/desactiver/").status_code == 403


def test_sub_dev_limited_to_roles(client, lead_dev, registration):
    sub = make_user("subdev@t.bj", User.DEVELOPER, roles=["audit"])
    staff_client(client, sub)
    assert client.get("/dev/journal/").status_code == 200
    assert client.get("/dev/livraisons/").status_code == 403
    assert client.get(f"/dev/livraisons/{registration.link.pk}/pdf/").status_code == 403
    assert client.get("/dev/equipe/").status_code == 403
    assert client.get("/espace/liens/").status_code == 403


def test_only_principal_admin_creates_sub_admins(client, admin):
    staff_client(client, admin)
    r = client.post("/espace/equipe/", {"full_name": "Sœur Esther", "email": "esther@t.bj", "roles": ["links", "documents"]})
    assert r.status_code == 200 and b"/invitation/" in r.content
    inv = Invitation.objects.get(email="esther@t.bj")
    assert inv.kind == "sub_admin" and inv.roles == ["documents", "links"]


def test_role_tampering_is_ignored(client, admin):
    staff_client(client, admin)
    client.post("/espace/equipe/", {"full_name": "X", "email": "x@t.bj", "roles": ["links", "dev_documents"]})
    assert not Invitation.objects.filter(email="x@t.bj").exists()  # choix invalide → refusé


def test_principal_admin_signup_flow(client, lead_dev):
    staff_client(client, lead_dev)
    client.post("/dev/comptes/administrateur-principal/", {"email": "", "full_name": ""})
    url = client.session.get("principal_invite_url") or ""
    client.get("/dev/comptes/")  # affiche (et consomme) le lien
    inv = Invitation.objects.get(kind="principal_admin")
    assert inv.usable
    anon = Client()
    token = "tok-" + "a" * 30
    inv.token_hash = crypto.token_hash(token)
    inv.save()
    page = anon.get(f"/inscription-administrateur/{token}/")
    assert page.status_code == 200
    r = anon.post(f"/inscription-administrateur/{token}/", {
        "full_name": "Admin Principal", "email": "chef@t.bj", "phone": "0198184759",
        "password1": "Un-Mot-De-Passe-Long-2026", "password2": "Un-Mot-De-Passe-Long-2026",
    })
    assert r.status_code == 302 and r["Location"].endswith("/connexion/code/")
    u = User.objects.get(email="chef@t.bj")
    assert u.is_principal_admin and not u.totp_confirmed
    # Lien à usage unique
    assert Client().get(f"/inscription-administrateur/{token}/").status_code == 404
    # Plus aucune nouvelle invitation possible
    client.post("/dev/comptes/administrateur-principal/", {})
    assert Invitation.objects.filter(kind="principal_admin").count() == 1


def test_weak_password_rejected(lead_dev):
    token = "tok-" + "b" * 30
    Invitation.objects.create(kind="sub_admin", email="w@t.bj", roles=["links"], token_hash=crypto.token_hash(token),
                              created_by=lead_dev, expires_at=timezone.now() + timedelta(hours=1))
    r = Client().post(f"/invitation/{token}/", {"full_name": "W", "email": "w@t.bj", "password1": "123456", "password2": "123456"})
    assert r.status_code == 200 and not User.objects.filter(email="w@t.bj").exists()


def test_invited_email_cannot_be_changed(lead_dev):
    token = "tok-" + "c" * 30
    Invitation.objects.create(kind="sub_admin", email="fixe@t.bj", roles=["links"], token_hash=crypto.token_hash(token),
                              created_by=lead_dev, expires_at=timezone.now() + timedelta(hours=1))
    Client().post(f"/invitation/{token}/", {"full_name": "F", "email": "autre@t.bj", "password1": "Un-Mot-De-Passe-Long-2026", "password2": "Un-Mot-De-Passe-Long-2026"})
    assert User.objects.filter(email="fixe@t.bj").exists() and not User.objects.filter(email="autre@t.bj").exists()


def test_expired_invitation(lead_dev):
    token = "tok-" + "d" * 30
    Invitation.objects.create(kind="sub_admin", email="e@t.bj", token_hash=crypto.token_hash(token),
                              created_by=lead_dev, expires_at=timezone.now() - timedelta(seconds=1))
    assert Client().get(f"/invitation/{token}/").status_code == 404


def test_link_creation_double_check(client, admin, event):
    staff_client(client, admin)
    base = {"event": event.pk, "label": "Paroisse X", "payer_name": "P", "payer_phone": "", "amount_received": 50000,
            "valid_days": 7, "cash_ack": "on"}
    r = client.post("/espace/liens/nouveau/", {**base, "quota": 50, "quota_confirm": 500})
    assert r.status_code == 200 and not RegistrationLink.objects.exists()
    r = client.post("/espace/liens/nouveau/", {**base, "quota": 500, "quota_confirm": 500})
    assert r.status_code == 200 and not RegistrationLink.objects.exists()  # 500 000 F attendus, 50 000 saisis
    r = client.post("/espace/liens/nouveau/", {**{k: v for k, v in base.items() if k != "cash_ack"}, "quota": 50, "quota_confirm": 50})
    assert not RegistrationLink.objects.exists()
    r = client.post("/espace/liens/nouveau/", {**base, "quota": 50, "quota_confirm": 50})
    assert r.status_code == 302
    link = RegistrationLink.objects.get()
    page = client.get(r["Location"]).content.decode()
    assert "/i/" in page  # lien affiché une fois
    assert "/i/" not in client.get(r["Location"]).content.decode()  # puis plus jamais
    assert AuditLog.objects.filter(action="link_created").exists()
    assert link.quota == 50


def test_purge_respects_retention(client, admin, registration):
    staff_client(client, admin)
    ev = registration.event
    r = client.post(f"/espace/evenements/{ev.pk}/vider/", {"confirm": "VIDER"})
    assert r.status_code == 403 and Registration.objects.exists()
    ev.ends_on = timezone.localdate() - timedelta(days=40)
    ev.starts_on = ev.ends_on
    ev.save()
    client.post(f"/espace/evenements/{ev.pk}/vider/", {"confirm": "VIDER"})
    ev.refresh_from_db()
    assert ev.is_purged and ev.purged_registrations == 1 and not Registration.objects.exists()


def test_auto_purge_command(registration):
    from django.core.management import call_command

    ev = registration.event
    ev.starts_on = ev.ends_on = timezone.localdate() - timedelta(days=100)
    ev.save()
    call_command("purge_expired", grace=15)
    ev.refresh_from_db()
    assert ev.is_purged and not Registration.objects.exists()


def test_suspended_account_is_logged_out(client, admin):
    staff_client(client, admin)
    User.objects.filter(pk=admin.pk).update(is_active=False)
    r = client.get("/espace/")
    assert r.status_code == 302


def test_csrf_enforced(admin):
    c = Client(enforce_csrf_checks=True)
    r = c.post("/connexion/", {"email": admin.email, "password": PWD})
    assert r.status_code == 403


def test_predeploy_creates_one_time_lead_dev_link(db, capsys):
    import re

    from django.core.management import call_command

    call_command("predeploy")
    url = re.search(r"/invitation/([\w\-]+)/", capsys.readouterr().out).group(1)
    page = Client().get(f"/invitation/{url}/").content.decode()
    assert "développeur principal" in page and "administrateur principal" not in page
    r = Client().post(f"/invitation/{url}/", {"full_name": "Dev Chef", "email": "chef-dev@t.bj",
                                               "password1": "Un-Mot-De-Passe-Long-2026", "password2": "Un-Mot-De-Passe-Long-2026"})
    assert r.status_code == 302
    assert User.objects.get(email="chef-dev@t.bj").is_lead_dev
    assert Client().get(f"/invitation/{url}/").status_code == 404  # usage unique
    call_command("predeploy")
    assert "déjà présent" in capsys.readouterr().out  # plus aucun nouveau lien


def test_2fa_pause_is_temporary_and_bounded(client, admin, settings):
    from core.security import two_factor_paused_until

    today = timezone.localdate()
    settings.KIDLINK_2FA_PAUSE_UNTIL = (today + timedelta(days=1)).isoformat()
    assert two_factor_paused_until()
    r = client.post("/connexion/", {"email": admin.email, "password": PWD})
    assert r.status_code == 302 and r["Location"] == "/espace/"
    page = client.get("/espace/").content.decode()
    assert "code de sécurité désactivé" in page
    # Date passée, trop lointaine ou illisible : la 2FA reste obligatoire
    for bad in [(today - timedelta(days=1)).isoformat(), (today + timedelta(days=30)).isoformat(), "demain", ""]:
        settings.KIDLINK_2FA_PAUSE_UNTIL = bad
        assert two_factor_paused_until() is None
        c = Client()
        c.post("/connexion/", {"email": admin.email, "password": PWD})
        assert c.get("/espace/").status_code == 302
