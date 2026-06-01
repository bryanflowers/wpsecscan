from __future__ import annotations

import csv
import io
from pathlib import Path

from ..models import ScanReport

# OWASP CSV-injection prefix chars: a leading =, +, -, @, or tab makes Excel
# treat the cell as a formula. Prefix a single-quote to neutralize.
_CSV_INJECTION_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value) -> str:
    """Neutralize CSV-formula injection per OWASP CSV Injection prevention guide."""
    s = "" if value is None else str(value)
    if s and s[0] in _CSV_INJECTION_PREFIX:
        return "'" + s
    return s


def render(report: ScanReport) -> str:
    from .. import confidence as _conf
    waf_detected = any(
        ("WAF" in (f.title or "") or "CDN detected" in (f.title or ""))
        for r in report.results if r.check_id == "waf"
        for f in r.findings
    )
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    has_client_summary = any(
        (f.extra or {}).get("client_summary")
        for r in report.results for f in r.findings
    )
    header = ["target", "scanned_at", "check_id", "check_name", "severity", "confidence",
              "title", "url", "evidence", "remediation", "cve"]
    if has_client_summary:
        header.append("client_summary")
    w.writerow(header)
    for r in report.results:
        for f in r.findings:
            row = [
                _safe_cell(report.target),
                _safe_cell(report.scanned_at),
                _safe_cell(r.check_id),
                _safe_cell(r.check_name),
                _safe_cell(f.severity),
                _safe_cell(_conf.compute_confidence(f, r.check_id, waf_detected=waf_detected)),
                _safe_cell(f.title),
                _safe_cell(f.url),
                _safe_cell((f.evidence or "").replace("\r", " ").replace("\n", " | ")[:1000]),
                _safe_cell((f.remediation or "").replace("\r", " ").replace("\n", " | ")[:1000]),
                _safe_cell((f.extra or {}).get("cve", "")),
            ]
            if has_client_summary:
                row.append(_safe_cell((f.extra or {}).get("client_summary", "")))
            w.writerow(row)
    return buf.getvalue()


def write(report: ScanReport, path: Path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(path, render(report))
    try:
        from .. import activity as _act
        _act.emit("reporter", f"CSV: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
