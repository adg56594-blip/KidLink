from django.urls import include, path, re_path

from core.views import auth, dev, espace, public

public_patterns = [
    path("", public.home, name="home"),
    path("scanner/", public.scanner, name="scanner"),
    re_path(r"^v/(?P<public_id>[A-Za-z0-9]{1,16})/?$", public.scan_shell, name="scan"),
    path("v/_/", public.scan_shell, name="scan_shell"),
    path("api/verify/", public.api_verify, name="api_verify"),
    re_path(r"^i/(?P<token>[A-Za-z0-9_\-]{20,64})/$", public.link_form, name="link"),
    path("hors-ligne/", public.offline, name="offline"),
]

auth_patterns = [
    path("connexion/", auth.login_view, name="login"),
    path("connexion/code/", auth.otp_view, name="otp"),
    path("deconnexion/", auth.logout_view, name="logout"),
    re_path(r"^invitation/(?P<token>[A-Za-z0-9_\-]{20,64})/$", auth.accept_invitation, name="invite"),
    re_path(r"^inscription-administrateur/(?P<token>[A-Za-z0-9_\-]{20,64})/$", auth.accept_invitation, name="register_admin"),
]

espace_patterns = [
    path("", espace.dashboard, name="dashboard"),
    path("evenements/", espace.events, name="events"),
    path("evenements/nouveau/", espace.event_edit, name="event_new"),
    path("evenements/<int:pk>/", espace.event_edit, name="event_edit"),
    path("evenements/<int:pk>/vider/", espace.event_purge, name="event_purge"),
    path("liens/", espace.links, name="links"),
    path("liens/nouveau/", espace.link_create, name="link_new"),
    path("liens/<int:pk>/", espace.link_detail, name="link_detail"),
    path("liens/<int:pk>/activer/", espace.link_toggle, name="link_toggle"),
    path("liens/<int:pk>/regenerer/", espace.link_regenerate, name="link_regenerate"),
    path("bracelets/<int:pk>/desactiver/", espace.registration_revoke, name="registration_revoke"),
    path("documents/", espace.documents, name="documents"),
    path("documents/<int:pk>/pdf/", espace.document_download, name="document_download"),
    path("equipe/", espace.team, name="team"),
    path("equipe/<int:pk>/", espace.team_member, name="team_member"),
    path("equipe/invitations/<int:pk>/annuler/", espace.invite_revoke, name="invite_revoke"),
    path("compte/", auth.change_password, name="account"),
]

dev_patterns = [
    path("", dev.dashboard, name="dashboard"),
    path("livraisons/", dev.deliveries, name="deliveries"),
    path("livraisons/groupe/", dev.deliveries_bulk, name="deliveries_bulk"),
    path("livraisons/<int:pk>/", dev.delivery_edit, name="delivery_edit"),
    path("livraisons/<int:pk>/pdf/", dev.pdf_download, name="pdf"),
    path("comptes/", dev.accounts, name="accounts"),
    path("comptes/administrateur-principal/", dev.principal_invite, name="principal_invite"),
    path("comptes/<int:pk>/action/", dev.account_action, name="account_action"),
    path("equipe/", dev.team, name="team"),
    path("equipe/<int:pk>/", dev.team_member, name="team_member"),
    path("invitations/<int:pk>/annuler/", dev.invite_revoke, name="invite_revoke"),
    path("journal/", dev.audit_log, name="audit"),
    path("reglages/", dev.site_settings, name="settings"),
    path("compte/", auth.change_password, name="account"),
]

urlpatterns = [
    path("", include((public_patterns, "public"))),
    path("", include((auth_patterns, "auth"))),
    path("espace/", include((espace_patterns, "espace"))),
    path("dev/", include((dev_patterns, "dev"))),
    path("sw.js", public.service_worker, name="sw"),
    path("manifest.webmanifest", public.manifest, name="manifest"),
    path("robots.txt", public.robots),
    path("healthz/", public.healthz),
]

handler403 = "core.views.errors.forbidden"
handler404 = "core.views.errors.not_found"
handler500 = "core.views.errors.server_error"
