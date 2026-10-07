#!/usr/bin/env python3
"""The site's images, derived from docs/logo.jpg (the logo as given, 1024x1024, on white). Writes into docs/:

    logo.png               640 px, as given (the page puts it on a white card, so it reads in both colour schemes)
    mark.png               the emblem alone (the circle, the rock and the gate), background transparent, 256 px
    favicon.png            64 px of the mark
    apple-touch-icon.png   180 px of the mark on white
    og.png                 1200x630, the social card

    python3 scripts/site_assets.py          # write them
    python3 scripts/site_assets.py --check  # exit 1 if the committed images differ from what this would write

Needs Pillow. The card's text is set in DejaVu Sans, which is the one font assumed present.
"""

import hashlib
import io
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
NAVY, BLUE, STONE = (26, 42, 58), (38, 94, 141), (213, 207, 197)
FONTS = ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]  # bold, regular


def font(size, bold=True):
    return ImageFont.truetype(FONTS[0 if bold else 1], size)


def png(img):
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def mark(src):
    """The emblem, cut out: crop to the circle's box, and make the white around it (reached from the corners) transparent."""
    box = src.crop((196, 146, 840, 700)).convert("RGBA")
    for seed in ((0, 0), (box.width - 1, 0), (0, box.height - 1), (box.width - 1, box.height - 1)):
        ImageDraw.floodfill(box, seed, (255, 255, 255, 0), thresh=60)
    side = max(box.size)
    sq = Image.new("RGBA", (side, side), (255, 255, 255, 0))
    sq.paste(box, ((side - box.width) // 2, (side - box.height) // 2))
    return sq.resize((256, 256), Image.LANCZOS)


def card(src):
    img = Image.new("RGB", (1200, 630), (255, 255, 255))
    logo = src.resize((560, 560), Image.LANCZOS)
    img.paste(logo, (40, 35))
    d = ImageDraw.Draw(img)
    d.rectangle((640, 0, 1200, 630), fill=(15, 20, 26))
    d.text((680, 150), "cancho-gateway", font=font(50), fill=(232, 236, 241))
    d.text((680, 238), "An auditable HTTP/1.1", font=font(34, False), fill=(168, 181, 196))
    d.text((680, 282), "reverse proxy.", font=font(34, False), fill=(168, 181, 196))
    for i, line in enumerate(("Strict parsing.", "Every limit refused by name.", "A report CI checks.")):
        d.text((680, 368 + 46 * i), line, font=font(27), fill=(111, 163, 214))
    d.text((680, 548), "Alpha. Built in cancho.", font=font(24, False), fill=(120, 134, 150))
    return img


def build():
    src = Image.open(DOCS / "logo.jpg").convert("RGB")
    m = mark(src)
    white = Image.new("RGB", (180, 180), (255, 255, 255))
    small = m.resize((148, 148), Image.LANCZOS)
    white.paste(small, (16, 16), small)
    return {
        "logo.png": png(src.resize((640, 640), Image.LANCZOS)),
        "mark.png": png(m),
        "favicon.png": png(m.resize((64, 64), Image.LANCZOS)),
        "apple-touch-icon.png": png(white),
        "og.png": png(card(src)),
    }


def main():
    files = build()
    if "--check" in sys.argv[1:]:
        stale = [n for n, data in files.items() if not (DOCS / n).exists() or hashlib.sha256((DOCS / n).read_bytes()).digest() != hashlib.sha256(data).digest()]
        print("stale: " + ", ".join(stale) if stale else "images are current")
        return 1 if stale else 0
    for n, data in files.items():
        (DOCS / n).write_bytes(data)
        print("wrote docs/%s (%d bytes)" % (n, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
