import secrets
from datetime import timedelta

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone

from .fields import EncryptedTextField
from .roles import ADMIN_ROLES, DEV_ROLES

CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"  # sans 0/O, 1/I/L, U : lisible à l'oral


def format_reference(n) -> str:
    return f"SK-{n:04d}" if n else ""


def new_public_id() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))


# ======================================================================= comptes
class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password, **extra):
        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra)
        user.set_password(password)
        user.full_clean(exclude=["password", "totp_secret"])
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    DEVELOPER = "developer"
    ADMIN = "admin"
    KINDS = [(DEVELOPER, "Développeur"), (ADMIN, "Administrateur")]

    email = models.EmailField("e-mail", unique=True)
    full_name = models.CharField("nom complet", max_length=120)
    phone = models.CharField("téléphone", max_length=30, blank=True)
    kind = models.CharField(max_length=12, choices=KINDS)
    is_principal = models.BooleanField(default=False)
    roles = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    date_joined = models.DateTimeField(default=timezone.now)
    totp_secret = EncryptedTextField(blank=True, default="")
    totp_confirmed = models.BooleanField(default=False)
    totp_last_step = models.BigIntegerField(default=0)

    objects = UserManager()
    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["full_name", "kind"]

    class Meta:
        constraints = [
            # Un seul administrateur principal et un seul développeur principal.
            models.UniqueConstraint(fields=["kind"], condition=models.Q(is_principal=True), name="one_principal_per_kind"),
        ]

    def __str__(self):
        return self.full_name

    @property
    def is_developer(self):
        return self.kind == self.DEVELOPER

    @property
    def is_admin(self):
        return self.kind == self.ADMIN

    @property
    def is_lead_dev(self):
        return self.is_developer and self.is_principal

    @property
    def is_principal_admin(self):
        return self.is_admin and self.is_principal

    def has_role(self, role: str) -> bool:
        if not self.is_active:
            return False
        if self.is_lead_dev:
            return True
        if self.is_principal_admin:
            return role in ADMIN_ROLES
        if self.is_admin:
            return role in ADMIN_ROLES and role in self.roles
        return role in self.roles  # sous-développeur

    @property
    def role_labels(self):
        if self.is_principal:
            return ["Tous les droits"]
        labels = {**DEV_ROLES, **ADMIN_ROLES}
        return [labels[r] for r in self.roles if r in labels]

    @property
    def title(self):
        if self.is_lead_dev:
            return "Développeur principal"
        if self.is_developer:
            return "Développeur"
        if self.is_principal_admin:
            return "Administrateur principal"
        return "Sous-administrateur"


class Invitation(models.Model):
    """Lien d'activation de compte, à usage unique, valable 72 h."""

    PRINCIPAL_ADMIN = "principal_admin"
    SUB_ADMIN = "sub_admin"
    SUB_DEV = "sub_dev"
    KINDS = [
        (PRINCIPAL_ADMIN, "Administrateur principal"),
        (SUB_ADMIN, "Sous-administrateur"),
        (SUB_DEV, "Sous-développeur"),
    ]
    kind = models.CharField(max_length=20, choices=KINDS)
    email = models.EmailField(blank=True)
    full_name = models.CharField(max_length=120, blank=True)
    roles = models.JSONField(default=list, blank=True)
    token_hash = models.CharField(max_length=64, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    revoked = models.BooleanField(default=False)

    @property
    def usable(self):
        return not self.used_at and not self.revoked and self.expires_at > timezone.now()


# ===================================================================== réglages
class SiteSettings(models.Model):
    IMMEDIATE, DELAYED, SCHEDULED, HOLD = "immediate", "delayed", "scheduled", "hold"
    DELIVERY_MODES = [
        (IMMEDIATE, "Immédiat"),
        (DELAYED, "Différé"),
        (SCHEDULED, "Programmé"),
        (HOLD, "Retenu (envoi manuel)"),
    ]
    admin_phone = models.CharField("téléphone de l'administrateur", max_length=30, default="+229 98 18 47 59")
    admin_whatsapp = models.CharField("WhatsApp de l'administrateur", max_length=30, default="+229 98 18 47 59")
    dev_whatsapp = models.CharField("WhatsApp du développeur", max_length=30, default="+229 67 32 43 61")
    dev_name = models.CharField("nom affiché du développeur", max_length=80, default="L'équipe technique Sèmè Kids")
    bracelet_line = models.CharField(
        "ligne d'urgence imprimée sous le QR", max_length=40, blank=True, default="Urgence : +229 98 18 47 59"
    )
    default_delivery_mode = models.CharField(max_length=12, choices=DELIVERY_MODES, default=HOLD)
    default_delay_hours = models.PositiveIntegerField(default=24)
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


# =================================================================== événements
class Event(models.Model):
    title = models.CharField("titre", max_length=140)
    location = models.CharField("lieu", max_length=140)
    description = models.TextField("message d'accueil", max_length=1200, blank=True)
    starts_on = models.DateField("début")
    ends_on = models.DateField("fin")
    registration_deadline = models.DateField("date limite d'inscription", null=True, blank=True)
    price_per_child = models.PositiveIntegerField("prix par enfant (FCFA)", default=0)
    retention_days = models.PositiveIntegerField("conservation des données après la fin (jours)", default=30)
    is_published = models.BooleanField("affiché sur l'accueil", default=True)
    created_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    purged_at = models.DateTimeField(null=True, blank=True)
    purged_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    purged_registrations = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-starts_on"]

    def __str__(self):
        return self.title

    @property
    def retention_until(self):
        return self.ends_on + timedelta(days=self.retention_days)

    @property
    def is_purged(self):
        return self.purged_at is not None

    @property
    def is_upcoming_or_live(self):
        return not self.is_purged and self.ends_on >= timezone.localdate()

    @property
    def retention_over(self):
        return timezone.localdate() > self.retention_until

    @property
    def registrations_open(self):
        if self.is_purged or self.ends_on < timezone.localdate():
            return False
        return self.registration_deadline is None or self.registration_deadline >= timezone.localdate()

    @classmethod
    def featured(cls):
        today = timezone.localdate()
        return cls.objects.filter(is_published=True, purged_at__isnull=True, ends_on__gte=today).order_by("starts_on")


# ============================================================ liens d'inscription
class RegistrationLink(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="links")
    label = models.CharField("famille ou paroisse", max_length=120)
    payer_name = EncryptedTextField("nom de la personne qui a payé")
    payer_phone = EncryptedTextField("téléphone de la personne qui a payé", blank=True)
    quota = models.PositiveIntegerField("nombre d'enfants payés")
    amount_received = models.PositiveIntegerField("montant encaissé (FCFA)", default=0)
    token_hash = models.CharField(max_length=64, unique=True)
    token_hint = models.CharField(max_length=6)
    expires_at = models.DateTimeField("lien valable jusqu'au")
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    last_registration_at = models.DateTimeField(null=True, blank=True)

    # Livraison des PDF : réglée UNIQUEMENT par les développeurs.
    delivery_mode = models.CharField(max_length=12, choices=SiteSettings.DELIVERY_MODES, default=SiteSettings.HOLD)
    delivery_delay_hours = models.PositiveIntegerField(default=24)
    delivery_scheduled_at = models.DateTimeField(null=True, blank=True)
    delivery_updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.label} ({self.quota})"

    @property
    def used(self):
        return self.registrations.count()

    @property
    def remaining(self):
        return max(self.quota - self.used, 0)

    @property
    def is_full(self):
        return self.used >= self.quota

    @property
    def is_usable(self):
        return (
            self.is_active
            and not self.is_full
            and self.expires_at > timezone.now()
            and self.event.registrations_open
        )

    @property
    def status_label(self):
        if not self.is_active:
            return "Désactivé"
        if self.is_full:
            return "Complet"
        if self.expires_at <= timezone.now():
            return "Expiré"
        if not self.event.registrations_open:
            return "Inscriptions closes"
        return "Actif"

    @property
    def release_at(self):
        """Moment où l'administration peut télécharger le PDF (None = jamais pour l'instant)."""
        if not self.last_registration_at:
            return None
        if self.delivery_mode == SiteSettings.IMMEDIATE:
            return self.last_registration_at
        if self.delivery_mode == SiteSettings.DELAYED:
            return self.last_registration_at + timedelta(hours=self.delivery_delay_hours)
        if self.delivery_mode == SiteSettings.SCHEDULED:
            return self.delivery_scheduled_at
        return None

    @property
    def is_released(self):
        r = self.release_at
        return r is not None and r <= timezone.now()


class Registration(models.Model):
    link = models.ForeignKey(RegistrationLink, on_delete=models.CASCADE, related_name="registrations")
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name="registrations")
    public_id = models.CharField(max_length=12, unique=True, default=new_public_id)
    reference = models.PositiveIntegerField(unique=True, null=True, blank=True)
    nom = EncryptedTextField()
    prenom = EncryptedTextField()
    parent_name = EncryptedTextField()
    parent_phone = EncryptedTextField()
    parent_phone2 = EncryptedTextField(blank=True)
    paroisse = EncryptedTextField()
    charge_name = EncryptedTextField(blank=True)
    charge_phone = EncryptedTextField(blank=True)
    qr_fragment = EncryptedTextField()
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["created_at"]

    @property
    def full_name(self):
        return f"{self.prenom} {self.nom.upper()}".strip()

    @property
    def ref_display(self):
        return format_reference(self.reference)

    @property
    def display_code(self):
        c = self.public_id
        return f"{c[:4]}-{c[4:8]}-{c[8:]}"


class ScanLog(models.Model):
    VALID, REVOKED, EXPIRED, FORGED, UNKNOWN = "valid", "revoked", "expired", "forged", "unknown"
    RESULTS = [(VALID, "Authentique"), (REVOKED, "Désactivé"), (EXPIRED, "Expiré"), (FORGED, "Falsifié"), (UNKNOWN, "Inconnu")]
    registration = models.ForeignKey(Registration, null=True, blank=True, on_delete=models.CASCADE, related_name="scans")
    result = models.CharField(max_length=10, choices=RESULTS)
    ip_hash = models.CharField(max_length=16)
    created_at = models.DateTimeField(auto_now_add=True)


class AuditLog(models.Model):
    actor = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    actor_label = models.CharField(max_length=160, blank=True)
    action = models.CharField(max_length=60)
    detail = models.CharField(max_length=300, blank=True)
    ip_hash = models.CharField(max_length=16, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
