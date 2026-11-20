"""Contrôle d'accès : qui peut voir / faire quoi."""
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from core import crypto
from core.models import AuditLog, Invitation, Registration, RegistrationLink, User

from .conftest import PWD, make_user, staff_client

ESPACE = ["/espace/", "/espace/compte/"]
DEV = ["/dev/", "/dev/pelerinages/", "/dev/pelerinages/nouveau/", "/dev/liens/", "/dev/liens/nouveau/", "/dev/bracelets/",
       "/dev/administrateur/", "/dev/equipe/", "/dev/journal/", "/dev/reglages/"]


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
    assert r.status_code == 429  # bloqué 15 min depuis cette IP, même avec le bon mot de passe
    other_ip = Client(REMOTE_ADDR="10.9.9.9").post("/connexion/", {"email": admin.email, "password": PWD})
    assert other_ip.status_code == 302  # le vrai administrateur, ailleurs, n'est pas bloqué
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


def test_admin_rights_without_qr_codes(client, admin, registration):
    """L'administrateur : gains + liens + inscrits. JAMAIS de QR code ni de PDF."""
    staff_client(client, admin)
    link = registration.link
    allowed = ["/espace/", "/espace/compte/", "/dev/compte/", "/dev/liens/", "/dev/liens/nouveau/", f"/dev/liens/{link.pk}/"]
    for url in allowed:
        assert client.get(url).status_code == 200, url
    pages = "".join(client.get(u).content.decode() for u in allowed)
    for secret in [registration.public_id, registration.qr_fragment, "/pdf/"]:
        assert secret not in pages, secret
    assert "HOUNSOU" in client.get(f"/dev/liens/{link.pk}/").content.decode()  # il voit les inscrits
    assert "développeurs génèrent les QR codes" in client.get(f"/dev/liens/{link.pk}/").content.decode()
    forbidden = ["/dev/", "/dev/pelerinages/", "/dev/pelerinages/nouveau/", f"/dev/pelerinages/{link.event_id}/vider/", "/dev/bracelets/",
                 f"/dev/liens/{link.pk}/pdf/", "/dev/administrateur/", "/dev/equipe/", "/dev/journal/", "/dev/reglages/", "/dev/vider-donnees-de-test/"]
    for url in forbidden:
        assert client.get(url).status_code == 403, url
    for url in ["/dev/administrateur/inscription/", "/dev/equipe/", "/dev/vider-donnees-de-test/", f"/dev/pelerinages/{link.event_id}/vider/"]:
        assert client.post(url).status_code == 403, url


def test_admin_creates_link_and_can_fill_it_himself(client, admin, event):
    staff_client(client, admin)
    r = client.post("/dev/liens/nouveau/", {"event": event.pk, "label": "Famille Patron", "payer_name": "P", "payer_phone": "",
                                             "amount_received": 2000, "valid_days": 7, "cash_ack": "on", "quota": 2, "quota_confirm": 2})
    assert r.status_code == 302
    page = client.get(r["Location"]).content.decode()
    assert "Remplir moi-même les fiches" in page and "/i/" in page


def test_every_dev_url_checks_rights_for_admin(client, admin, registration):
    """Le préfixe /dev/ n'est plus bloqué en bloc : on vérifie que CHAQUE adresse protège ses données."""
    from django.urls import get_resolver

    staff_client(client, admin)
    ok = {"dev:links", "dev:link_new", "dev:link_detail", "dev:account", "dev:link_toggle", "dev:link_regenerate", "dev:registration_revoke",
          "dev:registration_edit"}
    resolver = get_resolver()
    names = [k for k in resolver.reverse_dict.keys() if isinstance(k, str)]
    dev_ns = resolver.namespace_dict["dev"][1]
    checked = 0
    for name in [n for n in dev_ns.reverse_dict.keys() if isinstance(n, str)]:
        if f"dev:{name}" in ok:
            continue
        pattern = dev_ns.reverse_dict.getlist(name)[0][0][0][0]
        url = "/dev/" + pattern.replace("%(pk)s", str(registration.link.pk))
        for method in ("get", "post"):
            code = getattr(client, method)(url).status_code
            assert code in (403, 405), (method, url, code)
        checked += 1
    assert checked >= 15 and names is not None


def test_admin_has_whatsapp_to_developers(client, admin):
    staff_client(client, admin)
    assert "wa.me/22967324361" in client.get("/espace/").content.decode()


def test_gains_survive_purge(client, admin, registration):
    from core.services import purge_event

    purge_event(registration.event)
    staff_client(client, admin)
    body = client.get("/espace/").content.decode()
    assert "3 000 F" in body  # montant conservé après l'effacement des enfants


def test_lead_dev_manages_everything(client, lead_dev, registration):
    staff_client(client, lead_dev)
    link = registration.link
    for url in DEV + ["/espace/", f"/dev/liens/{link.pk}/"]:
        assert client.get(url).status_code == 200, url
    r = client.get(f"/dev/liens/{link.pk}/pdf/")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    page = client.get("/dev/").content.decode()
    assert "Mode d'emploi" in page  # chaque fonction est expliquée


def test_sub_dev_limited_to_roles(client, lead_dev, registration):
    sub = make_user("subdev@t.bj", User.DEVELOPER, roles=["audit"])
    staff_client(client, sub)
    assert client.get("/dev/journal/").status_code == 200
    assert client.get("/dev/bracelets/").status_code == 403
    assert client.get(f"/dev/liens/{registration.link.pk}/pdf/").status_code == 403
    assert client.get("/dev/equipe/").status_code == 403
    assert client.get("/dev/liens/").status_code == 403
    assert client.get("/espace/").status_code == 200  # tout développeur peut voir les gains


def test_sub_dev_links_only_cannot_see_children(client, lead_dev, registration):
    sub = make_user("links@t.bj", User.DEVELOPER, roles=["links"])
    staff_client(client, sub)
    body = client.get(f"/dev/liens/{registration.link.pk}/").content.decode()
    assert "HOUNSOU" not in body
    assert client.post(f"/dev/enfants/{registration.pk}/bracelet/").status_code == 403


def test_only_lead_dev_invites_developers_and_roles_are_whitelisted(client, lead_dev):
    staff_client(client, lead_dev)
    r = client.post("/dev/equipe/", {"full_name": "Dev 2", "email": "dev2@t.bj", "roles": ["links", "documents"]})
    assert r.status_code == 200 and b"/invitation/" in r.content
    assert Invitation.objects.get(email="dev2@t.bj").roles == ["documents", "links"]
    client.post("/dev/equipe/", {"full_name": "X", "email": "x@t.bj", "roles": ["links", "gains", "superuser"]})
    assert not Invitation.objects.filter(email="x@t.bj").exists()  # rôle inconnu -> refusé


def test_principal_admin_signup_flow(client, lead_dev):
    staff_client(client, lead_dev)
    client.post("/dev/administrateur/inscription/", {"email": "", "full_name": ""})
    client.get("/dev/administrateur/")  # affiche (et consomme) le lien
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
    client.post("/dev/administrateur/inscription/", {})
    assert Invitation.objects.filter(kind="principal_admin").count() == 1


def test_weak_password_rejected(lead_dev):
    token = "tok-" + "b" * 30
    Invitation.objects.create(kind="sub_dev", email="w@t.bj", roles=["links"], token_hash=crypto.token_hash(token),
                              created_by=lead_dev, expires_at=timezone.now() + timedelta(hours=1))
    r = Client().post(f"/invitation/{token}/", {"full_name": "W", "email": "w@t.bj", "password1": "123456", "password2": "123456"})
    assert r.status_code == 200 and not User.objects.filter(email="w@t.bj").exists()


def test_invited_email_cannot_be_changed(lead_dev):
    token = "tok-" + "c" * 30
    Invitation.objects.create(kind="sub_dev", email="fixe@t.bj", roles=["links"], token_hash=crypto.token_hash(token),
                              created_by=lead_dev, expires_at=timezone.now() + timedelta(hours=1))
    Client().post(f"/invitation/{token}/", {"full_name": "F", "email": "autre@t.bj", "password1": "Un-Mot-De-Passe-Long-2026", "password2": "Un-Mot-De-Passe-Long-2026"})
    assert User.objects.filter(email="fixe@t.bj").exists() and not User.objects.filter(email="autre@t.bj").exists()


def test_expired_invitation(lead_dev):
    token = "tok-" + "d" * 30
    Invitation.objects.create(kind="sub_dev", email="e@t.bj", token_hash=crypto.token_hash(token),
                              created_by=lead_dev, expires_at=timezone.now() - timedelta(seconds=1))
    assert Client().get(f"/invitation/{token}/").status_code == 404


def test_link_creation_double_check(client, lead_dev, event):
    staff_client(client, lead_dev)
    base = {"event": event.pk, "label": "Paroisse X", "payer_name": "P", "payer_phone": "", "amount_received": 50000,
            "valid_days": 7, "cash_ack": "on"}
    r = client.post("/dev/liens/nouveau/", {**base, "quota": 50, "quota_confirm": 500})
    assert r.status_code == 200 and not RegistrationLink.objects.exists()
    r = client.post("/dev/liens/nouveau/", {**base, "quota": 500, "quota_confirm": 500})
    assert r.status_code == 200 and not RegistrationLink.objects.exists()  # 500 000 F attendus, 50 000 saisis
    r = client.post("/dev/liens/nouveau/", {**{k: v for k, v in base.items() if k != "cash_ack"}, "quota": 50, "quota_confirm": 50})
    assert not RegistrationLink.objects.exists()
    r = client.post("/dev/liens/nouveau/", {**base, "quota": 50, "quota_confirm": 50})
    assert r.status_code == 302
    link = RegistrationLink.objects.get()
    page = client.get(r["Location"]).content.decode()
    assert "/i/" in page  # lien affiché une fois
    assert "/i/" not in client.get(r["Location"]).content.decode()  # puis plus jamais
    assert AuditLog.objects.filter(action="link_created").exists()
    assert link.quota == 50


def fresh_code(user):
    """Code TOTP valide et jamais utilisé (le dernier utilisé est oublié pour le test)."""
    import time

    import pyotp

    from .conftest import SECRET

    User.objects.filter(pk=user.pk).update(totp_last_step=0)
    return pyotp.TOTP(SECRET).at(int(time.time()))


def test_purge_respects_retention(client, lead_dev, registration):
    sub = make_user("purge@t.bj", User.DEVELOPER, roles=["purge"])
    staff_client(client, sub)
    ev = registration.event
    r = client.post(f"/dev/pelerinages/{ev.pk}/vider/", {"confirm": "VIDER", "password": PWD, "code": fresh_code(sub)})
    assert r.status_code == 403 and Registration.objects.exists()
    ev.ends_on = timezone.localdate() - timedelta(days=40)
    ev.starts_on = ev.ends_on
    ev.save()
    # sans mot de passe / avec un mauvais code : rien n'est effacé
    client.post(f"/dev/pelerinages/{ev.pk}/vider/", {"confirm": "VIDER"})
    client.post(f"/dev/pelerinages/{ev.pk}/vider/", {"confirm": "VIDER", "password": PWD, "code": "000000"})
    ev.refresh_from_db()
    assert not ev.is_purged and Registration.objects.exists()
    client.post(f"/dev/pelerinages/{ev.pk}/vider/", {"confirm": "VIDER", "password": PWD, "code": fresh_code(sub)})
    ev.refresh_from_db()
    assert ev.is_purged and ev.purged_registrations == 1 and not Registration.objects.exists()
    assert ev.purged_amount == 3000 and ev.purged_places == 3 and ev.purged_links == 1


RESET_URL = "/dev/vider-donnees-de-test/"


def reset_payload(user, children=1, **over):
    from core.forms import RESET_PHRASE

    d = {"understand_all": "on", "understand_bracelets": "on", "understand_test": "on", "children": children,
         "phrase": RESET_PHRASE, "password": PWD, "code": fresh_code(user)}
    d.update(over)
    return {k: v for k, v in d.items() if v is not None}


def test_reset_data_only_for_lead_dev(client, lead_dev, admin, registration):
    every_role = make_user("all@t.bj", User.DEVELOPER, roles=["events", "links", "registrations", "documents", "purge", "accounts", "audit", "settings"])
    for u in (every_role, admin):
        c = Client()
        staff_client(c, u)
        assert c.get(RESET_URL).status_code == 403
        assert c.post(RESET_URL, reset_payload(u)).status_code == 403
    assert Registration.objects.count() == 1


@pytest.mark.parametrize("bad", [
    {"password": "mauvais-mot-de-passe"}, {"code": "123456"}, {"code": None}, {"children": 5},
    {"phrase": "effacer"}, {"understand_test": None}, {"understand_all": None},
])
def test_reset_data_refused_without_every_answer(client, lead_dev, registration, bad):
    staff_client(client, lead_dev)
    r = client.post(RESET_URL, reset_payload(lead_dev, **bad))
    assert r.status_code == 200 and Registration.objects.count() == 1 and RegistrationLink.objects.exists()
    assert AuditLog.objects.filter(action="reauth_failed").exists()


def test_reset_data_three_failures_logout(client, lead_dev, registration):
    staff_client(client, lead_dev)
    for _ in range(3):
        client.post(RESET_URL, reset_payload(lead_dev, password="faux"))
    r = client.post(RESET_URL, reset_payload(lead_dev))  # même avec les bonnes réponses : bloqué
    assert r.status_code == 302 and "/connexion/" in r["Location"]
    assert Registration.objects.count() == 1
    assert client.get("/dev/").status_code == 302  # déconnecté


def test_reset_data_success(client, lead_dev, admin, registration):
    from core.models import Event, ScanLog, SiteSettings

    staff_client(client, lead_dev)
    page = client.get(RESET_URL).content.decode()
    assert "Vider les données de test" in page
    r = client.post(RESET_URL, reset_payload(lead_dev))
    assert r.status_code == 302
    assert not Event.objects.exists() and not RegistrationLink.objects.exists() and not Registration.objects.exists() and not ScanLog.objects.exists()
    assert User.objects.filter(pk__in=[lead_dev.pk, admin.pk]).count() == 2 and SiteSettings.objects.exists()
    assert AuditLog.objects.filter(action="all_data_reset").exists()
    c = Client()
    staff_client(c, admin)
    assert "0 F" in c.get("/espace/").content.decode()  # gains remis à zéro


def test_reset_code_cannot_be_replayed(client, lead_dev, registration):
    staff_client(client, lead_dev)
    code = fresh_code(lead_dev)
    client.post(RESET_URL, reset_payload(lead_dev, children=99, code=code))  # code consommé ? non : refus avant
    payload = reset_payload(lead_dev, code=code)
    User.objects.filter(pk=lead_dev.pk).update(totp_last_step=10**12)  # le code a déjà servi
    client.post(RESET_URL, payload)
    assert Registration.objects.count() == 1


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
    """Sans jeton valide, la connexion n'a pas lieu (on recharge simplement la page)."""
    c = Client(enforce_csrf_checks=True)
    r = c.post("/connexion/", {"email": admin.email, "password": PWD})
    assert r.status_code == 302 and "rt=1" in r["Location"]
    assert "_auth_user_id" not in c.session


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


def test_remember_me_keeps_session_30_days(admin):
    import time

    import pyotp

    from .conftest import SECRET

    for remember, expected in [(True, 30 * 24 * 3600), (False, 0)]:
        User.objects.filter(pk=admin.pk).update(totp_last_step=0)
        c = Client()
        data = {"email": admin.email, "password": PWD}
        if remember:
            data["remember"] = "on"
        c.post("/connexion/", data)
        c.post("/connexion/code/", {"code": pyotp.TOTP(SECRET).at(int(time.time()))})
        assert c.session.get("otp_ok")
        assert c.session.get_expiry_age() == expected if expected else c.session.get_expire_at_browser_close()


def test_gestion_manifest_opens_login(client, db):
    import json

    r = client.get("/gestion.webmanifest")
    assert r.status_code == 200 and json.loads(r.content)["start_url"] == "/connexion/"


def test_dev_phone_shown_to_admin(client, lead_dev, admin):
    staff_client(client, lead_dev)
    client.post("/dev/compte/", {"action": "profile", "full_name": "Modeste Dev", "phone": "01 67 32 43 61"})
    c = Client()
    staff_client(c, admin)
    page = c.get("/espace/").content.decode()
    assert "Modeste Dev" in page and "wa.me/2290167324361" in page


def test_forgotten_password_flow_for_admin(client, lead_dev, admin):
    staff_client(client, lead_dev)
    r = client.post(f"/dev/comptes/{admin.pk}/mot-de-passe/")
    assert r.status_code == 302
    page = client.get("/dev/administrateur/").content.decode()
    token = __import__("re").search(r"/nouveau-mot-de-passe/([\w\-]+)/", page).group(1)
    assert "/nouveau-mot-de-passe/" not in client.get("/dev/administrateur/").content.decode()  # affiché une seule fois
    # l'administrateur avait une session ouverte : elle sera fermée par le changement
    old = Client()
    staff_client(old, admin)
    anon = Client()
    assert anon.get(f"/nouveau-mot-de-passe/{token}/").status_code == 200
    assert anon.post(f"/nouveau-mot-de-passe/{token}/", {"password1": "123", "password2": "123"}).status_code == 200  # trop faible
    new = "Nouveau-Mot-De-Passe-2026!"
    r = anon.post(f"/nouveau-mot-de-passe/{token}/", {"password1": new, "password2": new})
    assert r.status_code == 302 and r["Location"].endswith("/connexion/")
    admin.refresh_from_db()
    assert admin.check_password(new)
    assert old.get("/espace/").status_code == 302  # ancienne session fermée
    assert Client().get(f"/nouveau-mot-de-passe/{token}/").status_code == 404  # usage unique
    # le code de sécurité reste exigé
    c = Client()
    c.post("/connexion/", {"email": admin.email, "password": new})
    assert c.get("/espace/").status_code == 302
    assert AuditLog.objects.filter(action="password_reset_done").exists()


def test_reset_link_permissions(client, lead_dev, admin):
    sub = make_user("acc@t.bj", User.DEVELOPER, roles=["accounts"])
    other = make_user("other@t.bj", User.DEVELOPER, roles=["audit"])
    c = Client(); staff_client(c, sub)
    assert c.post(f"/dev/comptes/{admin.pk}/mot-de-passe/").status_code == 302  # rôle « comptes » : OK pour l'admin
    assert c.post(f"/dev/comptes/{other.pk}/mot-de-passe/").status_code == 403  # pas pour un développeur
    assert c.post(f"/dev/comptes/{lead_dev.pk}/mot-de-passe/").status_code == 403
    c2 = Client(); staff_client(c2, admin)
    assert c2.post(f"/dev/comptes/{admin.pk}/mot-de-passe/").status_code == 403  # l'admin ne peut rien générer
    c3 = Client(); staff_client(c3, lead_dev)
    assert c3.post(f"/dev/comptes/{other.pk}/mot-de-passe/").status_code == 302
    assert c3.post(f"/dev/comptes/{lead_dev.pk}/mot-de-passe/").status_code == 403  # pas pour soi-même


def test_reset_token_cannot_create_account(lead_dev, admin):
    from core.services import create_password_reset_link

    url = create_password_reset_link(admin, lead_dev)
    token = url.rstrip("/").rsplit("/", 1)[1]
    assert Client().get(f"/invitation/{token}/").status_code == 404
    assert Client().get(f"/inscription-administrateur/{token}/").status_code == 404


def test_reset_password_command_for_lead_dev(lead_dev, capsys):
    from django.core.management import call_command

    call_command("reset_password", email=lead_dev.email, reset_2fa=True)
    out = capsys.readouterr().out
    assert "/nouveau-mot-de-passe/" in out
    lead_dev.refresh_from_db()
    assert not lead_dev.totp_confirmed


def test_lead_dev_deletes_test_admin_then_invites_real_one(client, lead_dev, admin, registration):
    url = f"/dev/administrateur/{admin.pk}/supprimer/"
    session_admin = Client()
    staff_client(session_admin, admin)
    staff_client(client, lead_dev)
    assert client.get(url).status_code == 200
    client.post(url, {"confirm": "SUPPRIMER", "password": "faux", "code": fresh_code(lead_dev)})
    client.post(url, {"confirm": "oui", "password": PWD, "code": fresh_code(lead_dev)})
    assert User.objects.filter(pk=admin.pk).exists()  # refusé
    r = client.post(url, {"confirm": "SUPPRIMER", "password": PWD, "code": fresh_code(lead_dev)})
    assert r.status_code == 302 and not User.objects.filter(pk=admin.pk).exists()
    assert RegistrationLink.objects.filter(pk=registration.link_id).exists()  # les paiements restent
    assert session_admin.get("/espace/").status_code == 302  # l'admin connecté est éjecté
    assert "Créer l'accès de l'administrateur" in client.get("/dev/administrateur/").content.decode()
    assert AuditLog.objects.filter(action="admin_deleted").exists()


def test_only_lead_dev_can_delete_admin(admin, lead_dev):
    acc = make_user("acc2@t.bj", User.DEVELOPER, roles=["accounts"])
    for u in (acc, admin):
        c = Client()
        staff_client(c, u)
        assert c.get(f"/dev/administrateur/{admin.pk}/supprimer/").status_code == 403
    c = Client()
    staff_client(c, lead_dev)
    assert c.get(f"/dev/administrateur/{lead_dev.pk}/supprimer/").status_code == 404  # pas un administrateur


EDIT = {"nom": "Hounsou", "prenom": "Marie-Claire", "parent_name": "Rosine Hounsou", "parent_phone": "01 96 11 22 33",
        "parent_phone2": "", "paroisse": "Paroisse Akpakpa", "charge_name": "", "charge_phone": ""}


def test_edit_registration_securely(client, lead_dev, registration):
    import json

    from core.qr import verify_fragment

    old_frag, ref = registration.qr_fragment, registration.ref_display
    url = f"/dev/enfants/{registration.pk}/modifier/"
    staff_client(client, lead_dev)
    assert client.get(url).status_code == 200
    # sans mot de passe / mauvais code : refusé
    client.post(url, EDIT)
    client.post(url, {**EDIT, "password": PWD, "code": "000000"})
    registration.refresh_from_db()
    assert registration.prenom == "Marie" and registration.qr_fragment == old_frag
    r = client.post(url, {**EDIT, "password": PWD, "code": fresh_code(lead_dev)})
    assert r.status_code == 302
    registration.refresh_from_db()
    assert registration.prenom == "Marie-Claire" and registration.parent_phone == "+2290196112233"
    assert registration.reprint_needed and registration.edit_count == 1 and registration.ref_display == ref
    d = verify_fragment(registration.public_id, registration.qr_fragment).data
    assert d["prenom"] == "Marie-Claire" and d["parent_phone"] == "+2290196112233" and d["ref"] == ref
    # l'ancien bracelet imprimé : « plus à jour », plus l'actuel : authentique
    v = lambda f: client.post("/api/verify/", data=json.dumps({"id": registration.public_id, "f": f}), content_type="application/json").json()["status"]
    assert v(old_frag) == "replaced" and v(registration.qr_fragment) == "valid"
    log = AuditLog.objects.get(action="registration_edited")
    assert "prénom" in log.detail and "numéro des parents" in log.detail and "Marie" not in log.detail  # pas de données personnelles
    # PDF des seuls bracelets corrigés, puis le marqueur disparaît
    r = client.get(f"/dev/liens/{registration.link_id}/pdf/?corriges=1")
    assert r.status_code == 200 and "corriges" in r["Content-Disposition"]
    registration.refresh_from_db()
    assert not registration.reprint_needed


def test_admin_can_correct_but_never_sees_qr(client, admin, registration):
    staff_client(client, admin)
    url = f"/dev/enfants/{registration.pk}/modifier/"
    page = client.get(url).content.decode()
    assert page and registration.qr_fragment not in page and registration.public_id not in page
    r = client.post(url, {**EDIT, "password": PWD, "code": fresh_code(admin)})
    assert r.status_code == 302
    registration.refresh_from_db()
    assert registration.prenom == "Marie-Claire"
    assert client.get(f"/dev/liens/{registration.link_id}/pdf/?corriges=1").status_code == 403


def test_edit_forbidden_without_registrations_role(client, lead_dev, registration):
    sub = make_user("links3@t.bj", User.DEVELOPER, roles=["links"])
    staff_client(client, sub)
    assert client.get(f"/dev/enfants/{registration.pk}/modifier/").status_code == 403


def test_saving_old_format_fiche_upgrades_qr(client, lead_dev, registration):
    from core.qr import SIGN_PREFIX, verify_fragment

    r = registration
    payload = f"1|20991231|{r.nom}|{r.prenom}|{r.parent_name}|{r.parent_phone}||{r.paroisse}||{r.ref_display}"
    old = crypto.b64u(payload.encode()) + "." + crypto.b64u(crypto.sign(f"{SIGN_PREFIX}|{r.public_id}|{payload}".encode()))
    Registration.objects.filter(pk=r.pk).update(qr_fragment=old, charge_name="Frère Paul")
    staff_client(client, lead_dev)
    same = {"nom": r.nom, "prenom": r.prenom, "parent_name": r.parent_name, "parent_phone": r.parent_phone, "parent_phone2": "",
            "paroisse": r.paroisse, "charge_name": "Frère Paul", "charge_phone": "", "password": PWD, "code": fresh_code(lead_dev)}
    client.post(f"/dev/enfants/{r.pk}/modifier/", same)
    r.refresh_from_db()
    d = verify_fragment(r.public_id, r.qr_fragment)
    assert d.payload.startswith("2|") and d.data["charge_name"] == "Frère Paul" and r.reprint_needed


def test_expired_security_token_on_login_recovers_gracefully(admin):
    """Page de connexion restée ouverte / ré-affichée : pas de page d'erreur, on réessaie simplement."""
    c = Client(enforce_csrf_checks=True)
    page = c.get("/connexion/")
    import re

    token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page.content.decode()).group(1)
    c.cookies["kl_csrf"] = "jeton-perime-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # le jeton du formulaire ne correspond plus
    r = c.post("/connexion/", {"csrfmiddlewaretoken": token, "email": admin.email, "password": PWD})
    assert r.status_code == 302 and r["Location"].startswith("/connexion/?")
    page = c.get(r["Location"]).content.decode()
    assert "la page vient d" in page and f'value="{admin.email}"' in page  # e-mail déjà rempli, pas d'erreur
    assert "Session expirée" not in page
    # Le nouvel essai fonctionne
    token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page).group(1)
    r = c.post(r["Location"], {"csrfmiddlewaretoken": token, "email": admin.email, "password": PWD})
    assert r.status_code == 302 and r["Location"].endswith("/connexion/code/")


def test_cookies_blocked_explained(admin):
    c = Client(enforce_csrf_checks=True)
    r = c.post("/connexion/?rt=1", {"email": admin.email, "password": PWD})  # aucun cookie envoyé
    assert r.status_code == 403 and "Cookies bloqués" in r.content.decode()


def test_expired_token_on_family_form_keeps_typed_data(link_factory):
    import re

    from .conftest import CHILD

    link = link_factory()
    c = Client(enforce_csrf_checks=True)
    c.get(f"/i/{link.raw_token}/")
    c.cookies["kl_csrf"] = "jeton-perime-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    r = c.post(f"/i/{link.raw_token}/", {**CHILD, "csrfmiddlewaretoken": "faux" * 8})
    assert r.status_code == 302
    page = c.get(r["Location"]).content.decode()
    assert 'value="Rosine Hounsou"' in page and 'value="Paroisse Akpakpa"' in page
    assert not Registration.objects.exists()  # rien n'a été enregistré sans jeton valide


def test_expired_token_on_logout_button_returns_to_page(admin):
    c = Client(enforce_csrf_checks=True)
    staff_client(c, admin)
    r = c.post("/deconnexion/", HTTP_REFERER="http://testserver/espace/")
    assert r.status_code == 302 and r["Location"].startswith("/espace/?")
