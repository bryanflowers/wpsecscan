"""E2 Findings heatmap — severity × OWASP-category grid as inline SVG.

Each cell is colored by finding count (white → red). Reporters embed the
output as inline SVG so the report stays a single self-contained .html file.
"""
from __future__ import annotations

import html as _html

from .models import ScanReport, SEVERITIES

# Stable ordering for the X-axis (OWASP 2021 categories the scanner produces).
OWASP_ORDER = (
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable & Outdated Components"),
    ("A07:2021", "Identification & Authn Failures"),
    ("A08:2021", "Software & Data Integrity Failures"),
    ("A09:2021", "Logging & Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery"),
)

# Severity order (Y-axis), top-down most critical first
SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _build_matrix(report: ScanReport, tags_map: dict) -> dict[tuple[str, str], int]:
    """Return {(severity, owasp_code): count}."""
    out: dict[tuple[str, str], int] = {}
    for res in report.results:
        cat = (tags_map.get(res.check_id) or {}).get("owasp")
        if not cat:
            continue
        for f in res.findings:
            key = (f.severity, cat)
            out[key] = out.get(key, 0) + 1
    return out


def _color_for(count: int, max_count: int, sev: str) -> str:
    """Heat color — white for 0, gradient up to a severity-themed peak."""
    if count <= 0:
        return "#f8f9fa"
    intensity = min(1.0, count / max(max_count, 1))
    # Base palette per severity row, blended with white based on intensity
    peak = {
        "critical": (192, 57, 43),
        "high":     (211, 84, 0),
        "medium":   (196, 119, 0),
        "low":      (127, 140, 141),
        "info":     (44, 62, 80),
    }.get(sev, (52, 73, 94))
    r = int(255 - (255 - peak[0]) * intensity)
    g = int(255 - (255 - peak[1]) * intensity)
    b = int(255 - (255 - peak[2]) * intensity)
    return f"#{r:02x}{g:02x}{b:02x}"


def render_svg(report: ScanReport, tags_map: dict | None = None, *,
                cell_w: int = 70, cell_h: int = 38) -> str:
    """Inline SVG suitable for embedding into the HTML report."""
    if tags_map is None:
        from . import tags as _t
        tags_map = _t._load()

    matrix = _build_matrix(report, tags_map)
    if not matrix:
        return ('<svg width="320" height="40" xmlns="http://www.w3.org/2000/svg">'
                '<text x="0" y="22" font-family="sans-serif" font-size="12" fill="#888">'
                'No findings to plot in heatmap.</text></svg>')

    max_count = max(matrix.values())

    label_w = 90          # left-side severity labels
    header_h = 32         # OWASP code labels at the top
    cols = len(OWASP_ORDER)
    rows = len(SEV_ORDER)
    total_w = label_w + cols * cell_w + 10
    total_h = header_h + rows * cell_h + 24

    parts: list[str] = [
        f'<svg width="{total_w}" height="{total_h}" xmlns="http://www.w3.org/2000/svg" '
        f'font-family="-apple-system, Segoe UI, sans-serif" font-size="11">',
    ]

    # Header row — OWASP codes
    for ci, (code, label) in enumerate(OWASP_ORDER):
        x = label_w + ci * cell_w + cell_w / 2
        parts.append(
            f'<text x="{x:.1f}" y="20" text-anchor="middle" fill="#333">'
            f'<title>{_html.escape(label)}</title>{_html.escape(code)}</text>'
        )

    # Rows
    for ri, sev in enumerate(SEV_ORDER):
        y = header_h + ri * cell_h
        # severity label (left)
        parts.append(
            f'<text x="{label_w - 8}" y="{y + cell_h / 2 + 4:.1f}" text-anchor="end" '
            f'font-weight="600" fill="#333">{sev.upper()}</text>'
        )
        for ci, (code, label) in enumerate(OWASP_ORDER):
            count = matrix.get((sev, code), 0)
            color = _color_for(count, max_count, sev)
            x = label_w + ci * cell_w
            text_color = "#fff" if count and count / max_count > 0.45 else "#222"
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_w - 2}" height="{cell_h - 2}" '
                f'fill="{color}" stroke="#e1e4e8" stroke-width="1">'
                f'<title>{sev.upper()} × {_html.escape(code)} ({_html.escape(label)}): '
                f'{count} finding(s)</title></rect>'
            )
            if count:
                cx = x + (cell_w - 2) / 2
                cy = y + (cell_h - 2) / 2 + 4
                parts.append(
                    f'<text x="{cx:.1f}" y="{cy:.1f}" text-anchor="middle" '
                    f'fill="{text_color}" font-weight="600">{count}</text>'
                )

    # Footer note
    parts.append(
        f'<text x="{label_w}" y="{total_h - 4}" fill="#888" font-size="10">'
        f'Severity × OWASP Top 10. Darker = more findings. '
        f'Peak per cell: {max_count}.</text>'
    )

    parts.append("</svg>")
    return "\n".join(parts)
