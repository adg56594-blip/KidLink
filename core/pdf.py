"""PDF d'impression des bracelets.

Format A4, 4 colonnes x 5 lignes = 20 bracelets par page.
QR de 40 mm (largement lisible : ~0,6 mm par module), dessiné en vectoriel
(net à toute résolution d'imprimante), nom et prénom en dessous, traits de coupe.
Le PDF est produit à la demande en mémoire : aucun fichier n'est stocké sur le serveur.
"""
import io
from pathlib import Path

import segno
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from .qr import qr_url

FONT_DIR = Path(__file__).resolve().parent / "fonts"
COLS, ROWS = 4, 5
PER_PAGE = COLS * ROWS
MARGIN_X, MARGIN_Y = 9 * mm, 12 * mm
QR_SIZE = 40 * mm
_fonts_ready = False


def _fonts():
    global _fonts_ready
    if not _fonts_ready:
        pdfmetrics.registerFont(TTFont("KL", str(FONT_DIR / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("KL-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf")))
        _fonts_ready = True


def _fit(c, text, font, size, max_w, min_size=6):
    while size > min_size and c.stringWidth(text, font, size) > max_w:
        size -= 0.25
    while c.stringWidth(text, font, size) > max_w and len(text) > 3:
        text = text[:-2] + "…"
    return text, size


def _draw_qr(c, data, x, y, size):
    qr = segno.make(data, error="m", micro=False)
    matrix = list(qr.matrix)
    n = len(matrix)
    quiet = 2
    m = size / (n + 2 * quiet)
    c.setFillColor(white)
    c.rect(x, y, size, size, stroke=0, fill=1)
    c.setFillColor(black)
    for r, row in enumerate(matrix):
        run = None
        for col, val in enumerate(list(row) + [0]):  # regroupe les modules en bandes
            if val and run is None:
                run = col
            elif not val and run is not None:
                c.rect(x + (quiet + run) * m, y + size - (quiet + r + 1) * m, (col - run) * m + 0.01, m + 0.01, stroke=0, fill=1)
                run = None
    return qr.version


def build_pdf(registrations, *, title: str, subtitle: str, bracelet_line: str = "") -> bytes:
    _fonts()
    buf = io.BytesIO()
    page_w, page_h = A4
    c = canvas.Canvas(buf, pagesize=A4, pageCompression=1)
    c.setTitle(title)
    c.setAuthor("KidLink")
    c.setCreator("KidLink")
    cell_w = (page_w - 2 * MARGIN_X) / COLS
    cell_h = (page_h - 2 * MARGIN_Y) / ROWS
    regs = list(registrations)
    pages = max(1, -(-len(regs) // PER_PAGE))

    for p in range(pages):
        chunk = regs[p * PER_PAGE : (p + 1) * PER_PAGE]
        # En-tête discret pour l'imprimeur
        c.setFont("KL", 7)
        c.setFillColor(HexColor("#5b6478"))
        c.drawString(MARGIN_X, page_h - 7 * mm, f"KidLink · {title} · {subtitle}")
        c.drawRightString(page_w - MARGIN_X, page_h - 7 * mm, f"Page {p + 1}/{pages} · {len(regs)} bracelet(s)")
        c.drawString(MARGIN_X, 5 * mm, "Découper le long des pointillés. Ne pas réduire la taille des QR codes à l'impression (échelle 100 %).")

        for i, reg in enumerate(chunk):
            col, row = i % COLS, i // COLS
            x0 = MARGIN_X + col * cell_w
            y0 = page_h - MARGIN_Y - (row + 1) * cell_h
            # traits de coupe
            c.setStrokeColor(HexColor("#9aa3b5"))
            c.setLineWidth(0.4)
            c.setDash(2, 2)
            c.rect(x0, y0, cell_w, cell_h, stroke=1, fill=0)
            c.setDash()
            qx = x0 + (cell_w - QR_SIZE) / 2
            qy = y0 + cell_h - QR_SIZE - 2 * mm
            _draw_qr(c, qr_url(reg.public_id, reg.qr_fragment), qx, qy, QR_SIZE)
            c.setFillColor(black)
            name, size = _fit(c, reg.full_name, "KL-Bold", 10, cell_w - 4 * mm)
            c.setFont("KL-Bold", size)
            c.drawCentredString(x0 + cell_w / 2, qy - 4.2 * mm, name)
            c.setFont("KL", 6.5)
            c.setFillColor(HexColor("#333a48"))
            c.drawCentredString(x0 + cell_w / 2, qy - 7.2 * mm, f"Code {reg.display_code}")
            if bracelet_line:
                line, s2 = _fit(c, bracelet_line, "KL", 6.5, cell_w - 4 * mm)
                c.setFont("KL", s2)
                c.drawCentredString(x0 + cell_w / 2, qy - 9.8 * mm, line)
        c.showPage()
    c.save()
    return buf.getvalue()
