"""M35 Org-level dashboard.

Aggregates risk scores from every snapshot in ~/.wpsecscan/reports/ grouped
by an optional "business unit" tag. A simple `units.json` config maps URLs
to a BU label; URLs not in the map fall under "Unassigned".

Output: standalone HTML page with per-BU summary cards + a flat table of
every URL ranked by latest risk score.
"""
from __future__ import annotations

import html as _html
import json
from collections import defaultdict
from pathlib import Path


def _units_map() -> dict[str, str]:
    """Load ~/.wpsecscan/units.json mapping URL -> business unit name."""
    from .. import history as _h
    p = Path(_h._home()) / "units.json"
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in d.items() if isinstance(k, str) and isinstance(v, str)}


def _latest_per_url() -> dict[str, dict]:
    """Return {url: {scanned_at, risk_score}} taking the most recent snapshot."""
    from .. import history as _h
    reports_dir = Path(_h._home()) / "reports"
    by_url: dict[str, dict] = {}
    if not reports_dir.exists():
        return {}
    # v2.8.5 M4 — pre-fix glob("*.json") included canonical aliases
    # like `latest.json` and any malformed sidecar. Restrict to the
    # `<host>-<timestamp>.json` shape used by history snapshots.
    for p in sorted(reports_dir.glob("*-*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        url = d.get("target", "?")
        ts = d.get("scanned_at", p.stem)
        prev = by_url.get(url)
        if prev is None or ts > prev.get("scanned_at", ""):
            by_url[url] = {"scanned_at": ts, "risk_score": int(d.get("risk_score", 0))}
    return by_url


def render() -> str:
    units = _units_map()
    latest = _latest_per_url()

    bu_data: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for url, info in latest.items():
        bu = units.get(url, "Unassigned")
        bu_data[bu].append((url, info))

    def card_color(avg: float) -> str:
        if avg >= 90: return "#1f8a3c"
        if avg >= 70: return "#c47700"
        if avg >= 40: return "#d35400"
        return "#c0392b"

    cards = []
    bus_sorted = sorted(bu_data.items())
    for bu, urls in bus_sorted:
        if not urls:
            continue
        avg = sum(i["risk_score"] for _u, i in urls) / len(urls)
        worst = min((i["risk_score"] for _u, i in urls), default=100)
        cards.append(
            f'<div class="card" style="border-color:{card_color(avg)}">'
            f'<h3>{_html.escape(bu)}</h3>'
            f'<div class="num" style="color:{card_color(avg)}">{avg:.0f}<span class="of">/100 avg</span></div>'
            f'<div class="sub">{len(urls)} site(s) · worst {worst}</div>'
            f'</div>'
        )

    rows = []
    for url, info in sorted(latest.items(), key=lambda x: x[1]["risk_score"]):
        bu = units.get(url, "Unassigned")
        rs = info["risk_score"]
        color = card_color(rs)
        rows.append(
            f'<tr><td>{_html.escape(bu)}</td>'
            f'<td><a href="{_html.escape(url)}" rel="noopener noreferrer">{_html.escape(url)}</a></td>'
            f'<td style="color:{color};font-weight:700">{rs}/100</td>'
            f'<td>{_html.escape(info["scanned_at"])}</td></tr>'
        )

    return f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>WPSecScan org dashboard</title>
<style>
  body{{margin:0;font:14px/1.5 -apple-system,Segoe UI,sans-serif;background:#0d1117;color:#e6edf3}}
  header{{padding:18px 22px;border-bottom:1px solid #30363d}}
  main{{max-width:1100px;margin:0 auto;padding:18px 22px}}
  .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
  .card{{background:#161b22;border-left:4px solid #30363d;padding:14px 18px;border-radius:6px;min-width:200px}}
  .card h3{{margin:0 0 6px;font-size:13px;text-transform:uppercase;color:#8b949e;letter-spacing:.06em}}
  .card .num{{font-size:28px;font-weight:700}}
  .card .num .of{{font-size:12px;color:#8b949e;margin-left:4px;font-weight:400}}
  .card .sub{{font-size:11px;color:#8b949e;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d}}
  th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #30363d;font-size:13px}}
  th{{background:#1f2630;color:#79c0ff}}
  a{{color:#79c0ff;text-decoration:none}} a:hover{{text-decoration:underline}}
  .empty{{color:#8b949e;font-style:italic;padding:24px;text-align:center}}
</style>
</head><body>
<header><h1 style="margin:0">WPSecScan — Org dashboard</h1>
<div style="color:#8b949e;font-size:12px;margin-top:4px">{len(latest)} site(s) across {len(bu_data)} business unit(s)</div>
</header>
<main>
<div class="cards">{"".join(cards)}</div>
{"<table><tr><th>Business unit</th><th>URL</th><th>Risk score</th><th>Last scanned</th></tr>" + "".join(rows) + "</table>" if rows else '<div class="empty">No snapshots yet. Run scans to populate the dashboard.</div>'}
</main></body></html>"""


def write(path: Path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(path, render())
