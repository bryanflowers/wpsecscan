"""C56 (v2.7.0) — OpenVEX (Vulnerability Exchange) export.

Emits one OpenVEX 0.2 document per scan. Each statement maps a CVE
(extracted from finding.extra.cve / extra.cves) to a status:

  not_affected   — the bundled CycloneDX SBOM shows the affected
                   package isn't present (or version doesn't match).
  affected       — finding found a CVE-listed component on the target.
  fixed          — finding indicates an upgrade-available with the
                   patched version reachable.
  under_investigation — fallback when CVE present but state unknown.

Complements the existing SBOM by mapping component versions to known
CVEs. Consumed by OSV, Grype, and most enterprise vulnerability
mgmt systems.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..models import ScanReport


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _classify(finding) -> str:
    """Return the VEX status for a finding."""
    extra = finding.extra if isinstance(finding.extra, dict) else {}
    if extra.get("patched_in"):
        return "fixed"
    if finding.severity in ("critical", "high"):
        return "affected"
    if finding.severity in ("medium", "low"):
        return "under_investigation"
    return "not_affected"


def build_document(report: ScanReport) -> dict:
    """Build the OpenVEX 0.2 document dict."""
    from .. import __version__
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://wpsecscan.dev/vex/{uuid.uuid4()}",
        "author": "WPSecScan",
        "role": "scanner",
        "timestamp": _now(),
        "version": 1,
        "tooling": f"wpsecscan {__version__}",
        "statements": [],
    }
    for r in report.results:
        for f in r.findings:
            extra = f.extra if isinstance(f.extra, dict) else {}
            cves: list[str] = []
            cve = (extra.get("cve") or "").strip()
            if cve:
                cves.append(cve)
            for c in (extra.get("cves") or []):
                if isinstance(c, str) and c.strip():
                    cves.append(c.strip())
            if not cves:
                continue
            status = _classify(f)
            for cve_id in cves:
                stmt = {
                    "vulnerability": {"name": cve_id},
                    "products": [{
                        "@id": report.target,
                        "subcomponents": [{"@id": f"plugin/{extra.get('plugin_slug', r.check_id)}"}],
                    }],
                    "status": status,
                    "timestamp": report.scanned_at or _now(),
                }
                if status == "affected":
                    stmt["action_statement"] = f.remediation[:500] if f.remediation else ""
                elif status == "fixed" and extra.get("patched_in"):
                    stmt["fixed_versions"] = [str(extra["patched_in"])]
                doc["statements"].append(stmt)
    return doc


def write(report: ScanReport, out_path: Path) -> dict:
    doc = build_document(report)
    out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc
