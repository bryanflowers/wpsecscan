"""WordPress Security Bingo card generator.

Round-64 #169 — produces a 5x5 bingo card of common WP-misconfig
findings. Print it before a scan; cross off each finding as it
appears. Hit a row/column/diagonal = bingo. A free centre square
makes it 24 distinct items.
"""
from __future__ import annotations

import random
from html import escape


# 30 short labels we draw from. Random pick of 24 to fill a 5x5
# (centre is "FREE").
_BINGO_ITEMS = [
    "Default 'admin' user",
    "wp-config.php in backup",
    "TLS 1.0 still enabled",
    "Plugin > 1yr stale",
    "REST /users/ open",
    "XML-RPC enabled",
    "No 2FA on admin",
    "Debug error in body",
    "Mixed content",
    "Missing HSTS",
    ".env in docroot",
    ".git/ exposed",
    "Weak password (admin)",
    "DOM-XSS in JS",
    "Theme editor on",
    "Open redirect",
    "CORS *",
    "SVG upload allowed",
    "No CSP header",
    "WP_DEBUG=true",
    "phpinfo() leak",
    "Composer.lock leaked",
    "Wordfence outdated",
    "User enum via author=1",
    "Old jQuery",
    "Cookie missing Secure",
    "WP version in HTML",
    "Backup.zip in docroot",
    "Auto-publish API",
    "Nulled plugin found",
]


def generate_card(seed: int | None = None) -> list[list[str]]:
    """Returns a 5x5 grid of strings. Center is "FREE"."""
    rng = random.Random(seed)
    pool = _BINGO_ITEMS.copy()
    rng.shuffle(pool)
    items = pool[:24]
    grid = [[""] * 5 for _ in range(5)]
    idx = 0
    for r in range(5):
        for c in range(5):
            if r == 2 and c == 2:
                grid[r][c] = "FREE"
            else:
                grid[r][c] = items[idx]
                idx += 1
    return grid


def render_html(card: list[list[str]]) -> str:
    rows = []
    for r in card:
        cells = "".join(f'<td>{escape(c)}</td>' for c in r)
        rows.append(f"<tr>{cells}</tr>")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>WP Security Bingo</title>
<style>
body {{ font-family: sans-serif; padding: 2em; }}
table {{ border-collapse: collapse; }}
td {{ border: 2px solid #444; width: 120px; height: 120px; text-align: center;
      vertical-align: middle; padding: 8px; font-size: 12px; }}
td:nth-child(3):nth-of-type(3) {{}}
h1 {{ text-align: center; }}
.subtitle {{ text-align: center; font-size: 0.85em; color: #777; }}
</style></head>
<body>
<h1>WordPress Security Bingo</h1>
<p class="subtitle">Cross off each finding as it appears. Row/col/diagonal = bingo.</p>
<table>{''.join(rows)}</table>
</body></html>
"""


def write_card(path: str, seed: int | None = None) -> None:
    from pathlib import Path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    p.write_text(render_html(generate_card(seed)), encoding="utf-8")
