from django import template

from ..utils import pretty_phone, wa_number

register = template.Library()


@register.filter
def fcfa(value):
    try:
        return f"{int(value):,}".replace(",", " ") + " F"
    except (TypeError, ValueError):
        return "—"


@register.filter
def phone(value):
    return pretty_phone(value or "")


@register.filter
def digits(value):
    return wa_number(value)


@register.filter
def pct(n, total):
    try:
        return max(0, min(100, round(100 * int(n) / int(total))))
    except (TypeError, ValueError, ZeroDivisionError):
        return 0
