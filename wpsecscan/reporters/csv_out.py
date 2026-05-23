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
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["target", "scanned_at", "check_id", "check_name", "severity", "title", "url", "evidence", "remediation", "cve"])
    for r in report.results:
        for f in r.findings:
            w.writerow([
                _safe_cell(report.target),
                _safe_cell(report.scanned_at),
                _safe_cell(r.check_id),
                _safe_cell(r.check_name),
                _safe_cell(f.severity),
                _safe_cell(f.title),
                _safe_cell(f.url),
                _safe_cell((f.evidence or "").replace("\r", " ").replace("\n", " | ")[:1000]),
                _safe_cell((f.remediation or "").replace("\r", " ").replace("\n", " | ")[:1000]),
                _safe_cell((f.extra or {}).get("cve", "")),
            ])
    return buf.getvalue()


def write(report: ScanReport, path: Path) -> None:
    path.write_text(render(report), encoding="utf-8")
    try:
        from .. import activity as _act
        _act.emit("reporter", f"CSV: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
