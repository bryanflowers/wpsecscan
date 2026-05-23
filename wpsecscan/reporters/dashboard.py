"""Batch dashboard reporter — single HTML across N scanned sites."""
from __future__ import annotations

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


def render(reports: list[tuple[ScanReport, str]]) -> str:
    """`reports` is a list of (ScanReport, per-site-html-filename) tuples."""
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
        rows.append({
            "target": rep.target,
            "summary": rep.summary,
            "worst": rep.worst_severity(),
            "duration_ms": rep.duration_ms,
            "html_filename": html_filename,
        })
    # Sort: worst-first
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
    rows.sort(key=lambda r: sev_rank.get(r["worst"], 5))

    return tmpl.render(
        reports=rows,
        totals=totals,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )


def write(reports: list[tuple[ScanReport, str]], path: Path) -> None:
    path.write_text(render(reports), encoding="utf-8")
