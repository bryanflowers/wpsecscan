"""C55 (v2.7.0) — per-finding heatmap timeline.

Generates an SVG heatmap: rows = (check_id, finding_title), columns =
saved snapshot timestamps, cells = severity colour. Lets the operator
see at a glance which findings have been persistent and which are
recently-emerged.

Output: standalone SVG with inline styles, suitable for embedding in
the agency dashboard or board 1-pager.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_SEV_COLOR = {
    "critical": "#67000d",
    "high":     "#c0392b",
    "medium":   "#d35400",
    "low":      "#2980b9",
    "info":     "#7f8c8d",
}


def _safe_id(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s)[:60]


def build_matrix(target: str) -> dict[str, Any]:
    """Walk snapshots and build {finding_key: [sev per snapshot]}."""
    try:
        from .. import history as _h
        snaps = _h.snapshot_history(target)
    except (ImportError, AttributeError):
        snaps = []
    snap_data: list[tuple[str, dict]] = []
    for p in snaps:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            snap_data.append((d.get("scanned_at", p.name), d))
        except (OSError, ValueError):
            continue
    if not snap_data:
        return {"snapshots": [], "rows": {}}

    rows: dict[tuple[str, str], list[str | None]] = {}
    for i, (_ts, data) in enumerate(snap_data):
        seen = set()
        for r in data.get("results", []):
            cid = r.get("check_id", "")
            for f in r.get("findings", []):
                key = (cid, (f.get("title") or "")[:80])
                seen.add(key)
                if key not in rows:
                    rows[key] = [None] * len(snap_data)
                rows[key][i] = f.get("severity") or "info"
        # Any key not seen this snapshot stays None for column i
    return {
        "snapshots": [ts for ts, _ in snap_data],
        "rows": rows,
    }


def render_svg(target: str, *, max_rows: int = 80) -> str:
    """Render the SVG heatmap. Truncates to `max_rows` for readability."""
    data = build_matrix(target)
    snaps = data["snapshots"]
    rows = data["rows"]
    if not snaps or not rows:
        return (
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 60'>"
            "<text x='20' y='35' font-family='sans-serif' fill='#7f8c8d'>"
            "No history available yet.</text></svg>"
        )

    # Sort rows by most-recent severity rank (critical first)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
    sorted_keys = sorted(
        rows,
        key=lambda k: (rank.get(rows[k][-1], 5), k),
    )[:max_rows]

    cell_w = 12
    cell_h = 16
    label_w = 320
    header_h = 24
    w = label_w + len(snaps) * cell_w + 20
    h = header_h + len(sorted_keys) * cell_h + 20

    parts: list[str] = [
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {w} {h}' "
        "font-family='ui-sans-serif, system-ui, sans-serif' font-size='11'>",
        f"<rect width='{w}' height='{h}' fill='#0d1117'/>",
        f"<text x='8' y='15' fill='#c9d1d9' font-weight='700'>"
        f"Finding heatmap — {target}</text>",
    ]
    # Cells
    for ri, key in enumerate(sorted_keys):
        cid, title = key
        y = header_h + ri * cell_h
        label = f"[{cid}] {title}"[:48]
        parts.append(
            f"<text x='8' y='{y + cell_h - 4}' fill='#c9d1d9'>{_xml_esc(label)}</text>"
        )
        for ci, sev in enumerate(rows[key]):
            x = label_w + ci * cell_w
            color = _SEV_COLOR.get(sev, "#161b22") if sev else "#161b22"
            parts.append(
                f"<rect x='{x}' y='{y}' width='{cell_w - 2}' height='{cell_h - 2}' "
                f"fill='{color}' stroke='#30363d' stroke-width='0.5'/>"
            )
    parts.append("</svg>")
    return "".join(parts)


def _xml_esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
              .replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;"))


def write(target: str, out_path: Path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(out_path, render_svg(target))
