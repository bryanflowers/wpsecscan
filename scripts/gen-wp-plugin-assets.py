"""Generate placeholder banner / icon / screenshot for the wp.org plugin
directory.

Produces:
  wp-plugin/wpsecscan-companion/assets/icon-128x128.png
  wp-plugin/wpsecscan-companion/assets/icon-256x256.png
  wp-plugin/wpsecscan-companion/assets/banner-772x250.png
  wp-plugin/wpsecscan-companion/assets/banner-1544x500.png
  wp-plugin/wpsecscan-companion/assets/screenshot-1.png
  wp-plugin/wpsecscan-companion/assets/screenshot-2.png
  wp-plugin/wpsecscan-companion/assets/screenshot-3.png

Placeholder = solid dark-blue background + bold "WPSecScan" + tagline.
Real designs go through a designer; this just satisfies wp.org's
"missing asset" check at submission time.

Requires Pillow (already a transitive dep of openpyxl):
    pip install Pillow

Usage:
    python scripts/gen-wp-plugin-assets.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "wp-plugin" / "wpsecscan-companion" / "assets"


BG = (13, 17, 23)             # GitHub dark
ACCENT = (47, 129, 247)       # GitHub blue
FG = (230, 237, 243)
MUTED = (139, 148, 158)


def _font(size: int):
    from PIL import ImageFont
    # Try a few common system fonts; fall back to default
    for fn in ("Arial.ttf", "DejaVuSans-Bold.ttf", "segoeui.ttf", "Helvetica.ttc"):
        try:
            return ImageFont.truetype(fn, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _text_centred(d, xy, text, font, fill):
    """Draw `text` centred at xy."""
    bbox = d.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text((xy[0] - tw // 2, xy[1] - th // 2), text, fill=fill, font=font)


def _icon(size: int, out: Path) -> None:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (size, size), BG)
    d = ImageDraw.Draw(img)
    # accent border ring
    pad = size // 12
    d.rounded_rectangle([pad, pad, size - pad, size - pad],
                         radius=size // 8, outline=ACCENT, width=max(2, size // 32))
    # big WP letter
    _text_centred(d, (size // 2, int(size * 0.42)),
                   "WP", _font(int(size * 0.45)), FG)
    # SecScan small under
    _text_centred(d, (size // 2, int(size * 0.78)),
                   "SecScan", _font(int(size * 0.16)), ACCENT)
    img.save(out, "PNG")


def _banner(w: int, h: int, out: Path) -> None:
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    # accent stripe down the left
    d.rectangle([0, 0, max(8, w // 60), h], fill=ACCENT)
    _text_centred(d, (w // 2, int(h * 0.40)),
                   "WPSecScan companion", _font(int(h * 0.22)), FG)
    _text_centred(d, (w // 2, int(h * 0.72)),
                   "Read-only diagnostics for the WPSecScan defensive scanner",
                   _font(int(h * 0.08)), MUTED)
    img.save(out, "PNG")


def _screenshot(idx: int, title: str, body: list[str], out: Path) -> None:
    from PIL import Image, ImageDraw
    w, h = 1200, 800
    img = Image.new("RGB", (w, h), (255, 255, 255))
    d = ImageDraw.Draw(img)
    # header bar
    d.rectangle([0, 0, w, 56], fill=BG)
    d.text((24, 16), f"WordPress admin — {idx}",
            fill=FG, font=_font(20))
    # title
    d.text((48, 96), title, fill=BG, font=_font(34))
    # body lines
    for i, line in enumerate(body):
        d.text((48, 168 + i * 36), line, fill=(60, 60, 60), font=_font(20))
    img.save(out, "PNG")


def main() -> int:
    try:
        import PIL  # noqa: F401
    except ImportError:
        print("pip install Pillow first", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)

    _icon(128, OUT / "icon-128x128.png")
    _icon(256, OUT / "icon-256x256.png")
    _banner(772, 250, OUT / "banner-772x250.png")
    _banner(1544, 500, OUT / "banner-1544x500.png")
    _screenshot(1, "Settings → WPSecScan",
                 ["[ Generate one-time token ]",
                   "",
                   "Token expires in 60 minutes if unused.",
                   "Token is invalidated on first successful read."],
                 OUT / "screenshot-1.png")
    _screenshot(2, "Activity log",
                 ["Mon 14:02   192.0.2.10   OK (15 plugins, 3 users)",
                   "Sun 09:30   192.0.2.10   OK (15 plugins, 3 users)",
                   "Sat 03:00   192.0.2.10   OK (15 plugins, 3 users)"],
                 OUT / "screenshot-2.png")
    _screenshot(3, "GET /wp-json/wpsecscan/v1/diagnostics",
                 ["{",
                   "  \"core\": { \"version\": \"6.7\", \"multisite\": false, ... },",
                   "  \"plugins\": [ ... 15 entries ... ],",
                   "  \"themes\": [ ... 4 entries ... ],",
                   "  \"users\": [ ... 3 entries (email hashed) ... ],",
                   "  \"site_health\": { \"critical\": [], \"recommended\": [...] }",
                   "}"],
                 OUT / "screenshot-3.png")
    print(f"wrote 7 placeholder assets to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
