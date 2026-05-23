"""Theme CVE matching against the Wordfence Intelligence DB."""
from __future__ import annotations

from .. import db as vulndb
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    themes: dict[str, str | None] = ctx.get("shared", {}).get("themes") or {}
    if not themes:
        findings.append(
            Finding(
                severity="info",
                title="No themes to cross-reference against CVE database",
                evidence="The theme-enumeration check did not discover any theme slugs.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    step = ctx.get("step") or (lambda _s: None)
    vulns, age, source = vulndb.load_local()
    if not vulns:
        findings.append(
            Finding(
                severity="info",
                title="Vulnerability database is empty — skipping theme CVE match",
                evidence="No cached or embedded vulnerability database found.",
                remediation="Run `wpsecscan --update-db` or click 'Refresh DB' in the GUI.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"cross-referencing {len(themes)} theme(s) against {len(vulns)} DB entries...")
    matched_any = False
    for slug, ver in themes.items():
        step(f"checking theme {slug} {ver or '(version unknown)'}...")
        matches = vulndb.find_for(vulns, "theme", slug, ver)
        for vuln in matches:
            matched_any = True
            refs = "\n".join(f"  - {r}" for r in vuln.references[:5])
            findings.append(
                Finding(
                    severity=vuln.severity,
                    title=f"Known vulnerability in theme {slug} {ver or '(unknown)'}: {vuln.title[:120]}",
                    evidence=(
                        f"  Theme:         {slug}\n"
                        f"  Installed:     {ver or 'unknown'}\n"
                        + (f"  Fixed in:      {vuln.fixed_in}\n" if vuln.fixed_in else "")
                        + (f"  CVE:           {vuln.cve}\n" if vuln.cve else "")
                        + (f"  CVSS:          {vuln.cvss}\n" if vuln.cvss else "")
                        + (f"  References:\n{refs}\n" if refs else "")
                    ),
                    remediation=f"Update theme '{slug}' to {vuln.fixed_in or 'the latest release'} via Appearance → Themes.",
                    url=client.url(f"/wp-content/themes/{slug}/"),
                    extra={
                        "cve": vuln.cve,
                        "cvss": vuln.cvss,
                        "fixed_in": vuln.fixed_in,
                        "references": vuln.references[:10],
                        "next_steps": [
                            f"wp theme update {slug} --version={vuln.fixed_in}" if vuln.fixed_in else f"wp theme update {slug}",
                            f'searchsploit "{slug} theme"',
                        ],
                    },
                )
            )

    if not matched_any:
        findings.append(
            Finding(
                severity="info",
                title=f"No known-vulnerable theme versions detected among {len(themes)} theme(s)",
                evidence=f"DB source: {source}; {len(vulns)} entries checked.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
