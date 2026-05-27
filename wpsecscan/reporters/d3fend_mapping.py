"""C59 (v2.7.0) — MITRE D3FEND mapping report.

Aggregates check_tags.json's `d3fend` field across the report's checks
and emits an HTML table grouping findings by defensive technique ID
(D3-FA, D3-IAA, etc.). Operators with an EDR / SIEM playbook already
indexed by D3FEND IDs can reference these directly.
"""
from __future__ import annotations

import html
import json
import sys
from collections import defaultdict
from pathlib import Path

from ..models import ScanReport


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent.parent / "data"


def _load_tags() -> dict[str, dict]:
    p = _data_dir() / "check_tags.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# MITRE D3FEND technique labels (subset — only those used in check_tags.json).
_D3FEND_LABELS = {
    "D3-FA":   "File Analysis",
    "D3-NTA":  "Network Traffic Analysis",
    "D3-IAA":  "Identifier Activity Analysis",
    "D3-CRO":  "Credential Rotation",
    "D3-DNS":  "DNS Monitoring",
    "D3-MA":   "Message Analysis",
    "D3-EAL":  "Executable Allowlisting",
    "D3-SBA":  "Software Behavior Analysis",
}


def build_mapping(report: ScanReport) -> dict[str, list[dict]]:
    """Return {d3fend_id: [finding-dict, ...]}."""
    tags = _load_tags()
    out: dict[str, list[dict]] = defaultdict(list)
    for r in report.results:
        d3f = (tags.get(r.check_id) or {}).get("d3fend") or "(unmapped)"
        for f in r.findings:
            out[d3f].append({
                "check_id": r.check_id,
                "severity": f.severity,
                "title": f.title,
            })
    return dict(out)


def render(report: ScanReport) -> str:
    mapping = build_mapping(report)
    if not mapping:
        return "<p>No findings to map.</p>"
    rows: list[str] = []
    for d3f in sorted(mapping):
        label = _D3FEND_LABELS.get(d3f, "")
        n = len(mapping[d3f])
        findings_html = "<ul>" + "".join(
            f"<li><b>{html.escape(item['severity'].upper())}</b> "
            f"[{html.escape(item['check_id'])}] {html.escape(item['title'])}</li>"
            for item in sorted(mapping[d3f], key=lambda i: i["severity"])
        ) + "</ul>"
        rows.append(
            f"<tr><td><code>{html.escape(d3f)}</code></td>"
            f"<td>{html.escape(label)}</td><td>{n}</td>"
            f"<td>{findings_html}</td></tr>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>MITRE D3FEND mapping — {html.escape(report.target)}</title>
<style>
  body {{ font: 13px -apple-system, "Segoe UI", sans-serif; color: #222; margin: 24px; }}
  h1 {{ font-size: 20pt; margin: 0 0 12px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; vertical-align: top; }}
  th {{ background: #34495e; color: #fff; text-align: left; }}
  code {{ font: 11pt ui-monospace, Consolas, monospace; }}
</style>
</head><body>
<h1>MITRE D3FEND mapping</h1>
<p><b>Target:</b> {html.escape(report.target)} · <b>Scanned:</b> {html.escape(report.scanned_at)}</p>
<table>
  <thead><tr><th>D3FEND ID</th><th>Technique</th><th>Findings</th><th>Details</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
</body></html>"""


def write(report: ScanReport, out_path: Path) -> None:
    out_path.write_text(render(report), encoding="utf-8")
