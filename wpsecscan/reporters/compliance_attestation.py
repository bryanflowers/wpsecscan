"""Item #51 — SOC2 / ISO-27001 attestation report.

For each compliance framework, lists every check that the scanner ran +
the framework-control it maps to + the worst severity of any finding
under that check. The result is a printable matrix an auditor can
use as machine-generated evidence that controls were exercised.

Frameworks surfaced (from data/compliance_v2.json + data/compliance_map.json):
  - SOC2 (mapped via NIST CSF 2.0 + ISO 27001:2022 since SOC2's TSC
    points to those frameworks for control content)
  - ISO 27001:2022 Annex A
  - PCI DSS 4.0
  - NIST 800-53 r5
  - HITRUST CSF v11.4
  - CMMC 2.0
  - NIST CSF 2.0
  - CIS Controls v8

Output: a self-contained HTML page suitable for printing as a PDF.
"""
from __future__ import annotations

import json
from html import escape
from pathlib import Path

from ..models import ScanReport


def _data_path(name: str) -> Path:
    return Path(__file__).parent.parent / "data" / name


def _load_json(name: str) -> dict:
    p = _data_path(name)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _worst_severity_per_check(report: ScanReport) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in report.results:
        cur = "info"
        for f in r.findings:
            if _SEV_RANK.get(f.severity, 0) > _SEV_RANK.get(cur, 0):
                cur = f.severity
        if r.findings:
            out[r.check_id] = cur
        else:
            out[r.check_id] = "info"  # check ran but produced nothing
    return out


def render(report: ScanReport) -> str:
    pci_nist_iso = _load_json("compliance_map.json")   # pci_dss / nist_800_53 / iso_27001
    extended = _load_json("compliance_v2.json")         # hitrust / cmmc / nist_csf / cis_v8 / iso_27001_2022

    worst = _worst_severity_per_check(report)
    target_url = escape(report.target)
    scanned = escape(report.scanned_at)

    # Build the unified rows table
    all_check_ids = sorted(set(pci_nist_iso) | set(extended) - {"_meta", "_schema"})
    rows: list[dict] = []
    for cid in all_check_ids:
        a = pci_nist_iso.get(cid) or {}
        b = extended.get(cid) or {}
        # Only include rows where THIS scan actually ran the check
        if cid not in worst:
            continue
        rows.append({
            "check_id": cid,
            "worst": worst[cid],
            "pci": a.get("pci_dss", ""),
            "nist53": a.get("nist_800_53", ""),
            "iso2013": a.get("iso_27001", ""),
            "hitrust": b.get("hitrust", ""),
            "cmmc": b.get("cmmc", ""),
            "nist_csf": b.get("nist_csf", ""),
            "cis_v8": b.get("cis_v8", ""),
            "iso2022": b.get("iso_27001_2022", ""),
        })

    sev_pill = {
        "critical": "background:#67000d;color:#ffd6d6",
        "high":     "background:#5a1816;color:#ff8a85",
        "medium":   "background:#4a3a10;color:#f0c674",
        "low":      "background:#133246;color:#79c0ff",
        "info":     "background:#21262d;color:#8b949e",
    }

    body_rows = []
    for row in rows:
        sev = row["worst"]
        body_rows.append(
            f"<tr>"
            f"<td><code>{escape(row['check_id'])}</code></td>"
            f"<td><span class=pill style='{sev_pill[sev]}'>{sev.upper()}</span></td>"
            f"<td>{escape(row['pci'])}</td>"
            f"<td>{escape(row['nist53'])}</td>"
            f"<td>{escape(row['iso2013'])}</td>"
            f"<td>{escape(row['iso2022'])}</td>"
            f"<td>{escape(row['nist_csf'])}</td>"
            f"<td>{escape(row['cis_v8'])}</td>"
            f"<td>{escape(row['hitrust'])}</td>"
            f"<td>{escape(row['cmmc'])}</td>"
            f"</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WPSecScan compliance attestation — {target_url}</title>
<style>
  @page {{ size: letter landscape; margin: 0.5in; }}
  body {{ font: 10pt -apple-system, "Segoe UI", sans-serif; color: #222; margin: 24px; }}
  h1 {{ font-size: 20pt; margin: 0 0 6px; }}
  .meta {{ color: #555; font-size: 10pt; margin-bottom: 14px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 9pt; margin-top: 12px; }}
  th, td {{ border: 1px solid #ddd; padding: 4px 6px; text-align: left; vertical-align: top; }}
  th {{ background: #34495e; color: #fff; font-weight: 600; }}
  .pill {{ display: inline-block; padding: 2px 6px; border-radius: 999px; font-size: 8pt; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; }}
  code {{ font: 9pt ui-monospace, Consolas, monospace; }}
  .footnote {{ font-size: 8pt; color: #777; margin-top: 14px; }}
  .noprint {{ background: #fffde7; border: 1px solid #fdd835; padding: 8px; margin-bottom: 12px; font-size: 9pt; }}
  @media print {{ .noprint {{ display: none; }} }}
</style>
</head>
<body>
<div class="noprint">Tip: open this file in your browser and <b>Print → Save as PDF</b> for the attestation PDF.</div>
<h1>WPSecScan compliance attestation</h1>
<div class="meta">
    <b>Target:</b> {target_url}<br>
    <b>Scanned:</b> {scanned}<br>
    <b>Risk score:</b> {report.risk_score}/100 ·
    <b>Checks exercised:</b> {len(rows)} ·
    <b>Frameworks mapped:</b> 8
</div>
<table>
    <thead><tr>
        <th>Check</th>
        <th>Worst severity</th>
        <th>PCI DSS 4.0</th>
        <th>NIST 800-53 r5</th>
        <th>ISO 27001:2013</th>
        <th>ISO 27001:2022 Annex A</th>
        <th>NIST CSF 2.0</th>
        <th>CIS Controls v8</th>
        <th>HITRUST CSF v11.4</th>
        <th>CMMC 2.0</th>
    </tr></thead>
    <tbody>
    {''.join(body_rows)}
    </tbody>
</table>
<p class="footnote">
    This attestation lists every WPSecScan check that ran against the target,
    mapped to the controls it exercises across eight major compliance frameworks.
    The "worst severity" column reflects the highest-severity finding produced
    by that check on this scan. Mapping data is sourced from
    <code>wpsecscan/data/compliance_map.json</code> and
    <code>wpsecscan/data/compliance_v2.json</code>; both files are open-source
    and inspectable.
</p>
<p>Auditor signature: ______________________________________________</p>
<p>Date:               ______________________________________________</p>
</body>
</html>
"""


def write(report: ScanReport, path: Path) -> None:
    path.write_text(render(report), encoding="utf-8")
