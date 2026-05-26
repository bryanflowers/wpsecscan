"""Item #54 — user-supplied Jinja2 report template.

`wpsecscan SITE --report-template my-branded.html.j2`

Loads the user's Jinja2 template and renders it with the same context the
built-in HTML reporter uses (a `report` ScanReport-shaped dict, the
`summary`, the `findings` list, and the rendered `now` string), so an
agency can fully white-label the output without forking the project.

The template runs through Jinja2 with `select_autoescape(['html','xml'])`
so curly-brace HTML in attributes is safe by default. If the caller
*needs* HTML to pass through unescaped (rendering pre-formatted evidence,
for example) they can use the `|safe` filter just as the built-in
template does.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanReport


def render(report: ScanReport, template_path: Path) -> str:
    template_path = Path(template_path).expanduser().resolve()
    if not template_path.exists():
        raise FileNotFoundError(f"Report template not found: {template_path}")

    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tpl = env.get_template(template_path.name)
    return tpl.render(
        report=report.to_dict(),
        target=report.target,
        scanned_at=report.scanned_at,
        risk_score=report.risk_score,
        summary=report.summary,
        worst=report.worst_severity(),
        findings=[f.to_dict() for f in report.all_findings],
        results=[r.to_dict() for r in report.results],
        now=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def write(report: ScanReport, template_path: Path, out_path: Path) -> None:
    out_path.write_text(render(report, template_path), encoding="utf-8")
