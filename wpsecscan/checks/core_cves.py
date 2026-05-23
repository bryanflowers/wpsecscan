"""WordPress core CVE matching against the Wordfence Intelligence DB."""
from __future__ import annotations

from .. import db as vulndb
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    ver = ctx.get("shared", {}).get("wp_version")
    if not ver:
        findings.append(
            Finding(
                severity="info",
                title="WordPress core version unknown — cannot match CVEs",
                evidence="The core_version check did not detect a version (good for security, blind for CVE matching).",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    step("loading vuln database...")
    vulns, age, source = vulndb.load_local()
    if not vulns:
        findings.append(
            Finding(
                severity="info",
                title="Vulnerability database is empty — skipping core CVE match",
                evidence="No cached or embedded vulnerability database found.",
                remediation="Run `wpsecscan --update-db` or click 'Refresh DB' in the GUI.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"matching WordPress {ver} against {len(vulns)} DB entries...")
    matches = vulndb.find_for(vulns, "core", "wordpress", ver)
    if not matches:
        # Some Wordfence entries use slug 'wp' or empty — check those too
        matches = vulndb.find_for(vulns, "core", "wp", ver) or vulndb.find_for(vulns, "core", "", ver)

    if not matches:
        findings.append(
            Finding(
                severity="info",
                title=f"No known core CVEs match installed WordPress {ver}",
                evidence=f"DB source: {source}; {len(vulns)} entries checked.",
                remediation="No action needed for core. Keep auto-updates enabled.",
                url=ctx["target"],
            )
        )
        return findings

    for vuln in matches:
        refs = "\n".join(f"  - {r}" for r in vuln.references[:5])
        evidence = (
            f"  Core version:  {ver}\n"
            f"  Vulnerable:    "
            + (f"< {vuln.affected_to}" if vuln.affected_to else f"< {vuln.fixed_in}" if vuln.fixed_in else "all versions")
            + (f"\n  Fixed in:      {vuln.fixed_in}" if vuln.fixed_in else "")
            + (f"\n  CVSS:          {vuln.cvss}" if vuln.cvss else "")
            + (f"\n  CVE:           {vuln.cve}" if vuln.cve else "")
            + (f"\n  References:\n{refs}" if refs else "")
        )
        findings.append(
            Finding(
                severity=vuln.severity,
                title=f"WordPress core {ver} affected by {vuln.cve or 'CVE'}: {vuln.title[:120]}",
                evidence=evidence,
                remediation=(
                    f"Update WordPress core to {vuln.fixed_in or 'the latest stable release'} via Dashboard → Updates. "
                    "Test in staging if you run heavy plugins."
                ),
                url=ctx["target"],
                extra={
                    "cve": vuln.cve,
                    "cvss": vuln.cvss,
                    "fixed_in": vuln.fixed_in,
                    "references": vuln.references[:10],
                    "next_steps": [
                        f"wp core update --version={vuln.fixed_in}" if vuln.fixed_in else "# Update WordPress to latest stable",
                        f"# Read advisory: {vuln.references[0]}" if vuln.references else "",
                    ],
                },
            )
        )
    return findings
