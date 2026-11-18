from .models import SiteSettings
from .roles import ADMIN_ROLES, DEV_ROLES
from .utils import pretty_phone, wa_number


def site(request):
    s = SiteSettings.get()
    user = getattr(request, "user", None)
    can = {r: user.has_role(r) for r in {**ADMIN_ROLES, **DEV_ROLES}} if user and user.is_authenticated else {}
    return {
        "can": can,
        "site": s,
        "admin_phone_tel": wa_number(s.admin_phone),
        "admin_phone_pretty": pretty_phone("+" + wa_number(s.admin_phone)),
        "admin_wa": wa_number(s.admin_whatsapp),
        "dev_wa": wa_number(s.dev_whatsapp),
        "dev_wa_pretty": pretty_phone("+" + wa_number(s.dev_whatsapp)),
    }
