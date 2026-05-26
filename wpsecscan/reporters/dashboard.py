"""Batch dashboard reporter — single HTML across N scanned sites.

Two modes:
- Default: compact table of all sites + per-severity counts + link to each
  site's full HTML report.
- Agency mode (`agency=True` from --agency-dashboard): adds per-site
  risk-score history sparklines pulled from ~/.wpsecscan/reports/{safe}-*.json,
  and respects ~/.wpsecscan/brand.json for the logo/colour/agency name in
  the header. Designed to be printed to PDF and handed to a non-technical
  client as a monthly posture summary.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanReport


def _template_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent.parent / "data"


# Block-character bar — uses Unicode block elements 0x2581-0x2588 (▁▂▃▄▅▆▇█).
# Renders inline in HTML / PDF / any monospace medium without needing JS or
# external assets.
_SPARK_BLOCKS = "▁▂▃▄▅▆▇█"


def _sparkline(scores: list[int]) -> str:
    """Return an 8-level block-character sparkline of recent risk scores.
    `scores` is in chronological order; we render at most the last 20."""
    if not scores:
        return ""
    last = scores[-20:]
    lo, hi = min(last), max(last)
    if hi == lo:
        # Constant — show a flat mid-level bar so the sparkline isn't empty.
        return _SPARK_BLOCKS[4] * len(last)
    span = hi - lo
    out = []
    for s in last:
        idx = int(round((s - lo) / span * (len(_SPARK_BLOCKS) - 1)))
        out.append(_SPARK_BLOCKS[idx])
    return "".join(out)


def _load_recent_scores(target: str) -> list[int]:
    """Pull the risk_score from each timestamped snapshot under
    ~/.wpsecscan/reports/ for this target. Oldest first."""
    try:
        from .. import history as _h
    except ImportError:
        return []
    snaps = _h.snapshot_history(target)
    out: list[int] = []
    for p in snaps:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rs = data.get("risk_score")
        if isinstance(rs, (int, float)):
            out.append(int(rs))
    return out


def render(reports: list[tuple[ScanReport, str]], *, agency: bool = False) -> str:
    """`reports` is a list of (ScanReport, per-site-html-filename) tuples.

    When `agency=True`, per-site rows gain a `spark` + `prior_score`
    fields, and the template adds the brand.json header (agency_name,
    logo_url, primary_color, footer_text).
    """
    env = Environment(
        loader=FileSystemLoader(str(_template_dir())),
        autoescape=select_autoescape(enabled_extensions=("html", "j2")),
    )
    tmpl = env.get_template("dashboard.html.j2")

    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    rows = []
    for rep, html_filename in reports:
        for sev, n in rep.summary.items():
            if sev in totals:
                totals[sev] += n
        row = {
            "target": rep.target,
            "summary": rep.summary,
            "worst": rep.worst_severity(),
            "duration_ms": rep.duration_ms,
            "html_filename": html_filename,
            "risk_score": rep.risk_score,
        }
        if agency:
            scores = _load_recent_scores(rep.target)
            row["spark"] = _sparkline(scores)
            row["scan_count"] = len(scores)
            row["prior_score"] = scores[-2] if len(scores) >= 2 else None
            row["delta_score"] = (rep.risk_score - row["prior_score"]) if row["prior_score"] is not None else None
        rows.append(row)
    # Sort: worst-first
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
    rows.sort(key=lambda r: sev_rank.get(r["worst"], 5))

    brand = {}
    if agency:
        try:
            from .. import branding as _branding
            brand = _branding.load_brand()
        except ImportError:
            brand = {}

    generated_at = datetime.now().isoformat(timespec="seconds")

    # #55 — machine-readable manifest embedded in the rendered page so
    # `wpsecscan diff-agency old.html new.html` can compare two dashboards
    # without re-scraping the HTML table.
    manifest = {
        "generated_at": generated_at,
        "totals": totals,
        "sites": [
            {
                "target": r["target"],
                "risk_score": r["risk_score"],
                "worst": r["worst"],
                "summary": r["summary"],
                "prior_score": r.get("prior_score"),
                "delta_score": r.get("delta_score"),
            }
            for r in rows
        ],
    }
    manifest_json = json.dumps(manifest, default=str)

    return tmpl.render(
        reports=rows,
        totals=totals,
        agency=agency,
        brand=brand,
        generated_at=generated_at,
        manifest_json=manifest_json,
    )


def write(reports: list[tuple[ScanReport, str]], path: Path, *,
          agency: bool = False) -> None:
    path.write_text(render(reports, agency=agency), encoding="utf-8")
