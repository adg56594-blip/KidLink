import json

import pytest
from datetime import timedelta

from django.utils import timezone

from core.models import Registration, RegistrationLink, ScanLog

from .conftest import CHILD

pytestmark = pytest.mark.django_db


def post_child(client, link, **extra):
    return client.post(f"/i/{link.raw_token}/", {**CHILD, **extra})


def test_link_form_registers_and_enforces_quota(client, link_factory):
    link = link_factory(quota=2)
    assert client.get(f"/i/{link.raw_token}/").status_code == 200
    assert post_child(client, link, prenom="A").status_code == 302
    assert post_child(client, link, prenom="B").status_code == 302
    r = post_child(client, link, prenom="C")
    assert r.status_code in (403, 410)
    assert Registration.objects.filter(link=link).count() == 2
    reg = Registration.objects.filter(link=link).first()
    assert reg.nom == "HOUNSOU" and reg.parent_phone == "+2290197000000"


def test_family_fields_prefilled_for_next_child(client, link_factory):
    link = link_factory(quota=3)
    post_child(client, link, prenom="A")
    r = client.get(f"/i/{link.raw_token}/?ok=1")
    form_html = r.content.decode().split('class="child-form')[1].split("</form>")[0]
    assert 'value="Rosine Hounsou"' in form_html  # famille pré-remplie
    assert 'value="HOUNSOU"' not in form_html  # mais pas le nom de l'enfant


def test_charge_fields_are_optional(client, link_factory):
    link = link_factory()
    assert post_child(client, link).status_code == 302


def test_duplicate_child_requires_confirmation(client, link_factory):
    link = link_factory(quota=5)
    post_child(client, link)
    r = post_child(client, link)
    assert r.status_code == 200 and "déjà inscrit".encode() in r.content
    assert Registration.objects.filter(link=link).count() == 1
    assert post_child(client, link, confirm_duplicate="1").status_code == 302
    assert Registration.objects.filter(link=link).count() == 2


def test_invalid_phone_rejected(client, link_factory):
    link = link_factory()
    r = post_child(client, link, parent_phone="abc")
    assert r.status_code == 200 and Registration.objects.count() == 0


def test_xss_payload_is_neutralised(client, link_factory):
    link = link_factory()
    post_child(client, link, prenom='<script>alert(1)</script>Ama')
    reg = Registration.objects.get()
    assert "<" not in reg.prenom
    r = client.get(f"/i/{link.raw_token}/")
    assert b"<script>alert(1)" not in r.content


def test_unknown_inactive_expired_links(client, link_factory):
    assert client.get("/i/" + "x" * 32 + "/").status_code == 404
    link = link_factory()
    link.is_active = False
    link.save()
    assert client.get(f"/i/{link.raw_token}/").status_code == 403
    link2 = link_factory()
    RegistrationLink.objects.filter(pk=link2.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
    assert client.get(f"/i/{link2.raw_token}/").status_code == 403
    assert post_child(client, link2).status_code == 403


def test_link_bruteforce_is_throttled(client, link_factory):
    codes = [client.get("/i/" + f"{i:032d}" + "/").status_code for i in range(40)]
    assert set(codes) == {404}  # toujours la même réponse, même après blocage (aucune information)
    # une fois bloquée, l'IP ne peut même plus utiliser un vrai lien pendant 15 min
    link = link_factory()
    assert client.get(f"/i/{link.raw_token}/").status_code == 404


def test_legit_heavy_use_not_blocked(client, link_factory):
    link = link_factory(quota=60)
    for i in range(60):
        assert client.get(f"/i/{link.raw_token}/").status_code == 200
        assert post_child(client, link, prenom=f"Enfant{i}").status_code == 302
    assert Registration.objects.filter(link=link).count() == 60


def test_public_pages_never_contain_qr_or_child_data(client, registration):
    for url in ["/", "/scanner/", f"/v/{registration.public_id}"]:
        body = client.get(url).content.decode()
        assert registration.qr_fragment not in body
        assert "HOUNSOU" not in body


def verify(client, reg_id, frag):
    return client.post("/api/verify/", data=json.dumps({"id": reg_id, "f": frag}), content_type="application/json")


def test_api_verify_states(client, registration):
    r = verify(client, registration.public_id, registration.qr_fragment).json()
    assert r["status"] == "valid"
    assert set(r) <= {"status", "checked_at", "event"}  # aucune donnée personnelle renvoyée
    assert verify(client, registration.public_id, registration.qr_fragment[:-3] + "AAA").json()["status"] == "forged"
    assert verify(client, "ZZZZZZZZZZZZ", registration.qr_fragment).json()["status"] == "forged"
    registration.revoked_at = timezone.now()
    registration.save()
    assert verify(client, registration.public_id, registration.qr_fragment).json()["status"] == "revoked"
    assert ScanLog.objects.filter(result="forged").count() == 2


def test_api_verify_after_purge_reports_expired(client, registration):
    from core.services import purge_event

    rid, frag = registration.public_id, registration.qr_fragment
    purge_event(registration.event)
    assert verify(client, rid, frag).json()["status"] == "expired"


def test_api_verify_rejects_garbage_and_rate_limits(client):
    assert client.post("/api/verify/", data="{", content_type="application/json").status_code == 400
    codes = [verify(client, "ABCDEFGHJKMN", "x.y").status_code for _ in range(65)]
    assert 429 in codes


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r["Content-Security-Policy"]
    assert r["X-Frame-Options"] == "DENY"
    assert r["X-Content-Type-Options"] == "nosniff"
    assert r["Referrer-Policy"] == "same-origin"
    assert "camera=(self)" in r["Permissions-Policy"]


def test_private_pages_are_not_cached(client, link_factory):
    link = link_factory()
    assert "no-store" in client.get(f"/i/{link.raw_token}/")["Cache-Control"]
    assert "no-store" in client.get("/connexion/")["Cache-Control"]


def test_service_worker_and_manifest(client):
    sw = client.get("/sw.js")
    assert sw.status_code == 200 and sw["Service-Worker-Allowed"] == "/"
    assert "/v/_/" in sw.content.decode() and "/espace/" in sw.content.decode()
    assert client.get("/manifest.webmanifest").status_code == 200


def test_service_worker_assets_all_exist(client):
    """Si un fichier listé manque, le mode hors ligne ne s'installe pas : on le vérifie."""
    import re

    from django.contrib.staticfiles import finders

    body = client.get("/sw.js").content.decode()
    for path in re.findall(r"'/static/([^']+)'", body):
        assert finders.find(path), path


def test_healthz_ok_when_database_is_migrated(client):
    r = client.get("/healthz/")
    assert r.status_code == 200 and r.content == b"ok"


@pytest.mark.parametrize("method", ["TRACE", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_unusual_http_methods_refused(client, method):
    for url in ["/", "/connexion/", "/espace/", "/api/verify/"]:
        assert client.generic(method, url).status_code == 405


def test_500_page_works_without_database(rf):
    from unittest import mock

    from core.views.errors import server_error

    with mock.patch("core.models.SiteSettings.get", side_effect=RuntimeError("base indisponible")):
        r = server_error(rf.get("/"))
    assert r.status_code == 500 and "Un problème est survenu" in r.content.decode()
