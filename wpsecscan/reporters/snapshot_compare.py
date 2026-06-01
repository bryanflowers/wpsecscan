"""Item #46 — side-by-side comparison of two snapshots of the SAME site.

Distinct from comparison_two_sites which compares two DIFFERENT sites.
This renders a single HTML page with three columns: "Fixed", "Unchanged",
"New" so an operator can see exactly which findings closed and which
opened between two scans of the same target.
"""
from __future__ import annotations

import json
from html import escape
from pathlib import Path


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _findings(report: dict, min_rank: int = 1) -> dict[str, dict]:
    """Return {f'{check_id}::{title}': {check_id, title, severity}}."""
    out: dict[str, dict] = {}
    for r in report.get("results", []) or []:
        cid = r.get("check_id", "")
        for f in r.get("findings", []) or []:
            sev = f.get("severity", "info")
            if _SEVERITY_RANK.get(sev, 0) < min_rank:
                continue
            title = f.get("title", "")
            out[f"{cid}::{title}"] = {
                "check_id": cid,
                "title": title,
                "severity": sev,
                "remediation": f.get("remediation", ""),
            }
    return out


def render(old_report: dict, new_report: dict) -> str:
    old = _findings(old_report)
    new = _findings(new_report)
    fixed_keys = sorted(old.keys() - new.keys())
    new_keys = sorted(new.keys() - old.keys())
    unchanged_keys = sorted(old.keys() & new.keys())

    def _col(keys: list[str], src: dict, kind: str) -> str:
        if not keys:
            return f"<p class=empty>none</p>"
        rows = []
        for k in keys:
            f = src[k]
            sev_class = "crit" if f["severity"] == "critical" else (
                "high" if f["severity"] == "high" else (
                "med"  if f["severity"] == "medium" else (
                "low"  if f["severity"] == "low" else "info")))
            rows.append(
                f'<li><span class="badge {sev_class}">'
                f'{escape(f["severity"])}</span> '
                f'<strong>{escape(f["title"])[:120]}</strong> '
                f'<span class="cid">[{escape(f["check_id"])}]</span></li>'
            )
        return "<ul>" + "\n".join(rows) + "</ul>"

    target_a = old_report.get("target", "?")
    target_b = new_report.get("target", "?")
    score_a = old_report.get("risk_score", "?")
    score_b = new_report.get("risk_score", "?")
    delta = ""
    try:
        d = int(score_b) - int(score_a)
        delta = (f' <span class="delta-up">+{d}</span>' if d > 0
                  else f' <span class="delta-dn">{d}</span>' if d < 0
                  else ' <span class="delta-flat">0</span>')
    except (ValueError, TypeError):
        pass

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WPSecScan snapshot diff — {escape(target_b)}</title>
<style>
  :root{{--bg:#0d1117;--panel:#161b22;--fg:#e6edf3;--muted:#8b949e;--border:#30363d;
        --fixed-bg:#0c2a18;--fixed-fg:#6cc474;
        --new-bg:#2a1010;--new-fg:#ff8a85;
        --same-bg:#21262d;--same-fg:#8b949e}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,"Segoe UI",sans-serif}}
  header{{padding:24px;border-bottom:1px solid var(--border)}}
  header h1{{margin:0 0 6px;font-size:22px}}
  header .meta{{color:var(--muted);font-size:13px}}
  main{{max-width:1400px;margin:0 auto;padding:24px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}}
  section{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}}
  section.fixed h2{{color:var(--fixed-fg)}}
  section.new   h2{{color:var(--new-fg)}}
  section.same  h2{{color:var(--same-fg)}}
  h2{{margin:0 0 12px;font-size:15px;letter-spacing:.04em;text-transform:uppercase}}
  ul{{list-style:none;margin:0;padding:0}}
  li{{padding:8px 0;border-bottom:1px solid var(--border)}}
  li:last-child{{border-bottom:none}}
  .badge{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-right:6px;vertical-align:middle}}
  .badge.crit{{background:#67000d;color:#ffd6d6}}
  .badge.high{{background:#5a1816;color:#ff8a85}}
  .badge.med {{background:#4a3a10;color:#f0c674}}
  .badge.low {{background:#133246;color:#79c0ff}}
  .badge.info{{background:#21262d;color:#8b949e}}
  .cid{{color:var(--muted);font-size:11px;font-family:ui-monospace,Consolas,monospace}}
  .empty{{color:var(--muted);font-style:italic}}
  .delta-up{{color:#ff5252;font-weight:700}}
  .delta-dn{{color:#6cc474;font-weight:700}}
  .delta-flat{{color:var(--muted)}}
  @media (max-width: 900px) {{ main{{grid-template-columns:1fr}} }}
  @media print {{ body{{background:#fff;color:#111}} section{{background:#fff;color:#111;border-color:#ccc}} li{{break-inside:avoid}} }}
</style>
</head>
<body>
<header>
  <h1>Snapshot diff — <span style="color:#79c0ff">{escape(target_b)}</span></h1>
  <div class="meta">Old scan {escape(old_report.get("scanned_at", "?"))} (score {score_a}/100) → New scan {escape(new_report.get("scanned_at", "?"))} (score {score_b}/100){delta}</div>
  <div class="meta">Fixed: {len(fixed_keys)} · New: {len(new_keys)} · Unchanged: {len(unchanged_keys)}</div>
</header>
<main>
  <section class="fixed">
    <h2>Fixed ({len(fixed_keys)})</h2>
    {_col(fixed_keys, old, "fixed")}
  </section>
  <section class="same">
    <h2>Unchanged ({len(unchanged_keys)})</h2>
    {_col(unchanged_keys, new, "same")}
  </section>
  <section class="new">
    <h2>New ({len(new_keys)})</h2>
    {_col(new_keys, new, "new")}
  </section>
</main>
</body>
</html>
"""


def write(old_path: Path, new_path: Path, out_path: Path) -> None:
    old = json.loads(old_path.read_text(encoding="utf-8"))
    new = json.loads(new_path.read_text(encoding="utf-8"))
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(out_path, render(old, new))
