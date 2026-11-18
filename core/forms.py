import re
from datetime import timedelta

from django import forms
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone

from .models import Event, RegistrationLink, SiteSettings, User
from .utils import normalize_phone

CTRL = re.compile(r"[\x00-\x1f\x7f<>]")


def clean_text(v: str) -> str:
    v = CTRL.sub("", v or "")
    return re.sub(r"\s+", " ", v).strip()


class TextField(forms.CharField):
    def clean(self, value):
        return super().clean(clean_text(value))


class PhoneField(forms.CharField):
    def __init__(self, *a, **kw):
        kw.setdefault("max_length", 25)
        super().__init__(*a, **kw)
        self.widget.input_type = "tel"
        self.widget.attrs.update({"inputmode": "tel", "autocomplete": "off", "placeholder": "01 97 00 00 00"})

    def clean(self, value):
        value = super().clean(value)
        if not value:
            return ""
        p = normalize_phone(value)
        if not p:
            raise forms.ValidationError("Numéro invalide. Exemple : 01 97 00 00 00 ou +234 803 000 0000.")
        return p


# ------------------------------------------------------------------ connexion
class LoginForm(forms.Form):
    email = forms.EmailField(label="Adresse e-mail", widget=forms.EmailInput(attrs={"autocomplete": "username", "autofocus": True}))
    password = forms.CharField(label="Mot de passe", strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))


class OTPForm(forms.Form):
    code = forms.CharField(
        label="Code à 6 chiffres",
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={"inputmode": "numeric", "autocomplete": "one-time-code", "pattern": "[0-9]{6}", "autofocus": True}),
    )

    def clean_code(self):
        c = re.sub(r"\D", "", self.cleaned_data["code"])
        if len(c) != 6:
            raise forms.ValidationError("Le code contient 6 chiffres.")
        return c


class SetPasswordForm(forms.Form):
    full_name = TextField(label="Nom complet", max_length=120)
    email = forms.EmailField(label="Adresse e-mail")
    phone = PhoneField(label="Téléphone", required=False)
    password1 = forms.CharField(label="Mot de passe (12 caractères minimum)", strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    password2 = forms.CharField(label="Confirmer le mot de passe", strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    def clean_email(self):
        e = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=e).exists():
            raise forms.ValidationError("Cette adresse est déjà utilisée.")
        return e

    def clean(self):
        d = super().clean()
        p1, p2 = d.get("password1"), d.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Les deux mots de passe ne sont pas identiques.")
        elif p1:
            try:
                validate_password(p1, User(email=d.get("email", ""), full_name=d.get("full_name", "")))
            except forms.ValidationError as e:
                self.add_error("password1", e)
        return d


class ChangePasswordForm(forms.Form):
    old = forms.CharField(label="Mot de passe actuel", strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}))
    password1 = forms.CharField(label="Nouveau mot de passe", strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    password2 = forms.CharField(label="Confirmer", strip=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    def __init__(self, user, *a, **kw):
        self.user = user
        super().__init__(*a, **kw)

    def clean(self):
        d = super().clean()
        if not self.user.check_password(d.get("old", "")):
            self.add_error("old", "Mot de passe actuel incorrect.")
        if d.get("password1") != d.get("password2"):
            self.add_error("password2", "Les deux mots de passe ne sont pas identiques.")
        elif d.get("password1"):
            try:
                validate_password(d["password1"], self.user)
            except forms.ValidationError as e:
                self.add_error("password1", e)
        return d


class InviteForm(forms.Form):
    full_name = TextField(label="Nom complet", max_length=120)
    email = forms.EmailField(label="Adresse e-mail")
    roles = forms.MultipleChoiceField(label="Droits accordés", widget=forms.CheckboxSelectMultiple, required=True)

    def __init__(self, *a, role_choices=None, **kw):
        super().__init__(*a, **kw)
        self.fields["roles"].choices = list(role_choices.items())

    def clean_email(self):
        e = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=e).exists():
            raise forms.ValidationError("Un compte existe déjà avec cette adresse.")
        return e


class RolesForm(forms.Form):
    roles = forms.MultipleChoiceField(label="Droits", widget=forms.CheckboxSelectMultiple, required=False)

    def __init__(self, *a, role_choices=None, **kw):
        super().__init__(*a, **kw)
        self.fields["roles"].choices = list(role_choices.items())


# ------------------------------------------------------------------ événements
class DateInput(forms.DateInput):
    input_type = "date"


class EventForm(forms.ModelForm):
    title = TextField(label="Titre de l'événement", max_length=140)
    location = TextField(label="Lieu", max_length=140)

    class Meta:
        model = Event
        fields = ["title", "location", "description", "starts_on", "ends_on", "registration_deadline", "price_per_child", "retention_days", "is_published"]
        widgets = {
            "starts_on": DateInput(format="%Y-%m-%d"),
            "ends_on": DateInput(format="%Y-%m-%d"),
            "registration_deadline": DateInput(format="%Y-%m-%d"),
            "description": forms.Textarea(attrs={"rows": 4, "maxlength": 1200}),
        }

    def clean_retention_days(self):
        v = self.cleaned_data["retention_days"]
        if not 1 <= v <= 365:
            raise forms.ValidationError("Entre 1 et 365 jours.")
        return v

    def clean(self):
        d = super().clean()
        s, e, dl = d.get("starts_on"), d.get("ends_on"), d.get("registration_deadline")
        if s and e and e < s:
            self.add_error("ends_on", "La fin doit être après le début.")
        if dl and e and dl > e:
            self.add_error("registration_deadline", "La date limite doit être avant la fin de l'événement.")
        if "description" in d:
            d["description"] = CTRL.sub("", d["description"] or "").strip()
        return d


class PurgeForm(forms.Form):
    confirm = forms.CharField(label="Tapez VIDER pour confirmer", max_length=10)

    def clean_confirm(self):
        if self.cleaned_data["confirm"].strip().upper() != "VIDER":
            raise forms.ValidationError("Tapez exactement VIDER.")
        return "VIDER"


# ------------------------------------------------------------------ liens
MAX_QUOTA = 2000


class LinkForm(forms.Form):
    event = forms.ModelChoiceField(label="Événement", queryset=Event.objects.none(), empty_label=None)
    label = TextField(label="Famille ou paroisse", max_length=120, widget=forms.TextInput(attrs={"placeholder": "Ex. Famille HOUNSOU ou Paroisse Akpakpa"}))
    payer_name = TextField(label="Nom de la personne qui a payé", max_length=120)
    payer_phone = PhoneField(label="Téléphone de la personne qui a payé", required=False)
    quota = forms.IntegerField(label="Nombre d'enfants payés", min_value=1, max_value=MAX_QUOTA)
    quota_confirm = forms.IntegerField(label="Retapez le nombre d'enfants", min_value=1, max_value=MAX_QUOTA)
    amount_received = forms.IntegerField(label="Montant encaissé (FCFA)", min_value=0, max_value=100_000_000)
    valid_days = forms.IntegerField(label="Lien valable pendant (jours)", min_value=1, max_value=90, initial=7)
    discount_ack = forms.BooleanField(label="J'ai accordé une réduction (montant inférieur au prix normal)", required=False)
    cash_ack = forms.BooleanField(label="Je confirme avoir encaissé ce montant pour exactement ce nombre d'enfants.", required=True)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        qs = Event.objects.filter(purged_at__isnull=True, ends_on__gte=timezone.localdate())
        self.fields["event"].queryset = qs

    def clean(self):
        d = super().clean()
        q, q2 = d.get("quota"), d.get("quota_confirm")
        if q and q2 and q != q2:
            self.add_error("quota_confirm", f"Les deux nombres ne correspondent pas ({q} ≠ {q2}). Vérifiez avant de continuer.")
        ev = d.get("event")
        if ev and q and q == q2 and ev.price_per_child:
            expected = ev.price_per_child * q
            amount = d.get("amount_received") or 0
            if amount < expected and not d.get("discount_ack"):
                self.add_error(
                    "amount_received",
                    f"{q} enfant(s) × {ev.price_per_child:,} F = {expected:,} F attendus, {amount:,} F saisis. "
                    "Corrigez le nombre d'enfants ou cochez « réduction ».".replace(",", " "),
                )
            if amount > expected * 3:
                self.add_error("amount_received", "Montant anormalement élevé : vérifiez la saisie.")
        return d


class ChildForm(forms.Form):
    nom = TextField(label="Nom de l'enfant", max_length=60, widget=forms.TextInput(attrs={"autocomplete": "off", "autocapitalize": "characters"}))
    prenom = TextField(label="Prénom(s) de l'enfant", max_length=60, widget=forms.TextInput(attrs={"autocomplete": "off"}))
    parent_name = TextField(label="Nom du papa ou de la maman", max_length=80)
    parent_phone = PhoneField(label="Numéro à appeler")
    parent_phone2 = PhoneField(label="Deuxième numéro", required=False)
    paroisse = TextField(label="Paroisse de l'enfant", max_length=80, widget=forms.TextInput(attrs={"placeholder": "Ex. Paroisse Cathédrale de Porto-Novo"}))
    charge_name = TextField(label="Nom du chargé", max_length=80, required=False)
    charge_phone = PhoneField(label="Numéro du chargé", required=False)
    confirm_duplicate = forms.BooleanField(required=False, widget=forms.HiddenInput)

    def clean(self):
        d = super().clean()
        if d.get("parent_phone") and d.get("parent_phone") == d.get("parent_phone2"):
            d["parent_phone2"] = ""
        return d


# ------------------------------------------------------------------ développeurs
class DateTimeInput(forms.DateTimeInput):
    input_type = "datetime-local"


class DeliveryForm(forms.Form):
    mode = forms.ChoiceField(label="Envoi du PDF à l'administration", choices=SiteSettings.DELIVERY_MODES)
    delay_hours = forms.IntegerField(label="Délai (heures)", min_value=1, max_value=24 * 60, required=False)
    scheduled_at = forms.DateTimeField(label="Date et heure d'envoi", required=False, widget=DateTimeInput(format="%Y-%m-%dT%H:%M"), input_formats=["%Y-%m-%dT%H:%M"])

    def clean(self):
        d = super().clean()
        if d.get("mode") == SiteSettings.DELAYED and not d.get("delay_hours"):
            self.add_error("delay_hours", "Indiquez le délai.")
        if d.get("mode") == SiteSettings.SCHEDULED:
            if not d.get("scheduled_at"):
                self.add_error("scheduled_at", "Indiquez la date d'envoi.")
        return d


class SettingsForm(forms.ModelForm):
    class Meta:
        model = SiteSettings
        fields = ["admin_phone", "admin_whatsapp", "dev_whatsapp", "dev_name", "bracelet_line", "default_delivery_mode", "default_delay_hours"]

    def clean(self):
        d = super().clean()
        for f in ["admin_phone", "admin_whatsapp", "dev_whatsapp"]:
            if d.get(f) and not normalize_phone(d[f]):
                self.add_error(f, "Numéro invalide.")
        for f in ["dev_name", "bracelet_line"]:
            if f in d:
                d[f] = clean_text(d[f])
        return d


def link_expiry(days: int):
    return timezone.now() + timedelta(days=days)
