"""SARIF 2.1.0 output — for ingestion into GitHub code scanning, Defender, etc."""
from __future__ import annotations

import json
from pathlib import Path

from .. import __version__ as _scanner_version
from ..models import ScanReport

SARIF_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}


def render(report: ScanReport) -> str:
    from .. import confidence as _conf
    waf_detected = any(
        ("WAF" in (f.title or "") or "CDN detected" in (f.title or ""))
        for r in report.results if r.check_id == "waf"
        for f in r.findings
    )
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for r in report.results:
        for f in r.findings:
            rule_id = f"{r.check_id}.{(f.extra or {}).get('cve','')}".rstrip(".")
            # B10 (v2.8.0) — Finding.title/evidence are Optional; the
            # pre-fix `[:120]` slice crashed AttributeError when either
            # was None. Coerce to empty string first (matches json_out's
            # discipline).
            _title = f.title or ""
            _evidence = f.evidence or ""
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": r.check_name,
                    "shortDescription": {"text": _title[:120]},
                    "fullDescription": {"text": _evidence[:1000]},
                    "helpUri": f.url or report.target,
                    "defaultConfiguration": {"level": SARIF_LEVEL.get(f.severity, "none")},
                }
            results.append({
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(f.severity, "none"),
                "message": {"text": _title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url or report.target},
                    }
                }],
                "properties": {
                    **(f.extra or {}),
                    "severity": f.severity,
                    "confidence": _conf.compute_confidence(f, r.check_id, waf_detected=waf_detected),
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                },
            })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WPSecScan",
                    "version": _scanner_version,
                    "informationUri": "https://github.com/bryanflowers/wpsecscan",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "originalUriBaseIds": {"TARGET": {"uri": report.target}},
        }],
    }, indent=2)


def write(report: ScanReport, path: Path) -> None:
    path.write_text(render(report), encoding="utf-8")
    try:
        from .. import activity as _act
        _act.emit("reporter", f"SARIF: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
