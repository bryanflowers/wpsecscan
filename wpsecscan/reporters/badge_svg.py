"""SVG status badge for repo READMEs.

Round-64 #91 — produces a shields.io-style SVG that shows the
current scan status: "wpsecscan: A+ (0 critical, 1 high)". Embeddable
in any README.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

_GRADE_COLOURS = {
    "A+": "#2e7d32", "A": "#388e3c", "B": "#fbc02d",
    "C": "#fb8c00", "D": "#e64a19", "F": "#b00020",
}


def _grade(summary: dict) -> str:
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    if crit > 0:
        return "F"
    if high > 0:
        return "D"
    if med > 2:
        return "C"
    if med > 0:
        return "B"
    return "A+" if summary.get("low", 0) == 0 else "A"


def render_badge_svg(summary: dict) -> str:
    """Return an SVG string (shields.io style)."""
    grade = _grade(summary)
    color = _GRADE_COLOURS.get(grade, "#777")
    label = "wpsecscan"
    crit = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    value = f"{grade} ({crit} crit / {high} high)"
    label_w = max(70, 7 * len(label) + 10)
    value_w = max(110, 7 * len(value) + 10)
    total = label_w + value_w
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20">'
        f'<linearGradient id="b" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<mask id="a"><rect width="{total}" height="20" rx="3" fill="#fff"/></mask>'
        f'<g mask="url(#a)">'
        f'<path fill="#555" d="M0 0h{label_w}v20H0z"/>'
        f'<path fill="{color}" d="M{label_w} 0h{value_w}v20H{label_w}z"/>'
        f'<path fill="url(#b)" d="M0 0h{total}v20H0z"/>'
        f'</g>'
        f'<g fill="#fff" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{label_w // 2}" y="14">{escape(label)}</text>'
        f'<text x="{label_w + value_w // 2}" y="14">{escape(value)}</text>'
        f'</g></svg>'
    )


def write_badge(path: str, summary: dict) -> None:
    from pathlib import Path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Symlink guard
    if p.is_symlink():
        p.unlink()
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(p, render_badge_svg(summary))
