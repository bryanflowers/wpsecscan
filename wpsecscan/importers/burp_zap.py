"""Item #76 — import Burp / ZAP project files into wpsecscan reports.

The existing reporters write Burp scope XML — handoff to a manual
pentester. The reverse pipeline was missing: when the pentester finishes,
re-import their findings into the wpsecscan history so they show up on
the agency dashboard alongside automated scans.

Supported inputs:

  Burp Suite scan export (XML, from "Issues → Save report → XML"):
      one <issue> element per finding, with <name>, <severity>,
      <confidence>, <host>, <path>, <issueBackground>, <remediation>,
      <issueDetail>.

  OWASP ZAP report.xml (from `zap-cli quick-scan -r report.xml` or the
  GUI's "File → Save XML Report"):
      one <alertitem> per finding.

Both produce a ScanReport that can be saved via wpsecscan's normal
history machinery — `history.save_snapshot(report)` — so the dashboard
picks them up the next time it renders.
"""
from __future__ import annotations

import re
from pathlib import Path

# S5: prefer defusedxml when available (blocks billion-laughs entity
# expansion + XXE on all Python versions). Falls back to stdlib for
# users who didn't install the [security] extra; print a one-time
# stderr warning so they know parsing is using the less-safe path.
try:
    from defusedxml import ElementTree as ET  # type: ignore[import-not-found]
    _ET_BACKEND = "defusedxml"
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]
    _ET_BACKEND = "stdlib"
    import sys as _sys
    print("warning: defusedxml not installed; using stdlib XML parser "
           "(vulnerable to billion-laughs DoS). pip install defusedxml.",
           file=_sys.stderr)

from ..models import CheckResult, Finding, ScanReport


_SEV_MAP = {
    # Burp severities
    "information": "info", "info": "info",
    "low": "low", "medium": "medium", "high": "high",
    "critical": "critical",
    # ZAP risk levels
    "informational": "info", "1": "low", "2": "medium", "3": "high", "4": "critical",
}


def _norm_severity(raw: str) -> str:
    return _SEV_MAP.get((raw or "").strip().lower(), "medium")


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def import_burp(xml_path: Path, target_override: str = "") -> ScanReport:
    """Parse a Burp Suite scan XML export. Returns a ScanReport.

    Burp's XML mixes target hosts in each issue; we pick the first <host>
    as the target (or `target_override` if given) and group all findings
    under one synthetic CheckResult `imported_burp`.
    """
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    findings: list[Finding] = []
    inferred_target = ""
    for issue in root.findall(".//issue"):
        name = (issue.findtext("name") or "").strip()
        sev = _norm_severity(issue.findtext("severity") or "")
        host_el = issue.find("host")
        host = host_el.text.strip() if host_el is not None and host_el.text else ""
        path = (issue.findtext("path") or "").strip()
        url = f"{host}{path}" if host and path else host
        background = (issue.findtext("issueBackground") or "").strip()
        detail = (issue.findtext("issueDetail") or "").strip()
        remediation = (issue.findtext("remediationBackground") or "").strip()
        evidence = re.sub(r"<[^>]+>", "", (detail or background))[:2000]
        findings.append(Finding(
            severity=sev, title=name,
            evidence=evidence,
            remediation=re.sub(r"<[^>]+>", "", remediation)[:2000],
            url=url,
            extra={"source": "burp"},
        ))
        if not inferred_target and host:
            inferred_target = host
    return ScanReport(
        target=(target_override or inferred_target or "imported"),
        scanned_at=_now_iso(),
        duration_ms=0,
        results=[CheckResult(check_id="imported_burp",
                              check_name="Imported from Burp Suite",
                              findings=findings)],
    )


def import_zap(xml_path: Path, target_override: str = "") -> ScanReport:
    """Parse an OWASP ZAP XML report. Returns a ScanReport.

    ZAP's XML has a top-level <OWASPZAPReport> with one <site> per host
    and per-host <alerts><alertitem>.
    """
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    findings: list[Finding] = []
    inferred_target = ""
    for site in root.findall(".//site"):
        host = site.get("name", "")
        if not inferred_target and host:
            inferred_target = host
        for alert in site.findall(".//alertitem"):
            name = (alert.findtext("alert") or alert.findtext("name") or "").strip()
            sev = _norm_severity(alert.findtext("riskcode") or alert.findtext("riskdesc") or "")
            desc = (alert.findtext("desc") or "").strip()
            solution = (alert.findtext("solution") or "").strip()
            instance_url = ""
            inst_el = alert.find(".//instance/uri")
            if inst_el is not None and inst_el.text:
                instance_url = inst_el.text.strip()
            findings.append(Finding(
                severity=sev, title=name,
                evidence=re.sub(r"<[^>]+>", "", desc)[:2000],
                remediation=re.sub(r"<[^>]+>", "", solution)[:2000],
                url=instance_url or host,
                extra={"source": "zap"},
            ))
    return ScanReport(
        target=(target_override or inferred_target or "imported"),
        scanned_at=_now_iso(),
        duration_ms=0,
        results=[CheckResult(check_id="imported_zap",
                              check_name="Imported from OWASP ZAP",
                              findings=findings)],
    )


def autoimport(path: Path, target_override: str = "") -> ScanReport:
    """Sniff the XML root to pick the right importer."""
    tree = ET.parse(str(path))
    root = tree.getroot()
    tag = (root.tag or "").lower()
    text = (root.text or "")
    if "zap" in tag or "OWASPZAP" in text:
        return import_zap(path, target_override)
    # Burp's root is <issues>.
    return import_burp(path, target_override)
