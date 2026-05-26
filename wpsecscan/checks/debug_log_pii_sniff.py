"""When /wp-content/debug.log is exposed, look for PII in the first 4 KB.

The existing exposed_files check flags `wp-content/debug.log` on a 200
response. This check downloads the first 4 KB and scans for email
addresses, credit-card-shaped digits, and US/UK national-ID patterns.
A debug log containing real customer PII is a GDPR/PCI-DSS reportable
incident, not just an "info disclosure" finding.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Credit-card-ish: 13-19 digits possibly separated. Bound to avoid CSS hashes.
_CC_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# Loose IP detection (most logs include them; signal of unstructured logging)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("probing /wp-content/debug.log for PII content...")
    r = await client.get("/wp-content/debug.log")
    if r is None or r.status_code != 200 or not r.text:
        return findings
    snippet = (r.text or "")[:4096]
    # Don't fire if the file is empty (touch'd debug.log is a common state)
    if len(snippet.strip()) < 20:
        return findings
    emails = set(_EMAIL_RE.findall(snippet))
    # Filter known noise (no-reply, framework defaults)
    emails = {e for e in emails if not any(n in e.lower()
              for n in ("noreply", "no-reply", "wordpress.org", "example.com"))}
    # Crude credit-card validation — drop matches with too few unique digits
    # (often timestamps or version strings).
    cc_candidates = [m.replace(" ", "").replace("-", "") for m in _CC_RE.findall(snippet)]
    cc_candidates = [c for c in cc_candidates if 13 <= len(c) <= 19 and len(set(c)) > 4]
    ips = set(_IP_RE.findall(snippet))
    findings_in_log: list[str] = []
    if emails:
        findings_in_log.append(f"{len(emails)} email address(es)")
    if cc_candidates:
        findings_in_log.append(f"{len(cc_candidates)} credit-card-shaped digit string(s)")
    if ips:
        findings_in_log.append(f"{len(ips)} IP address(es)")
    if not findings_in_log:
        # debug.log exposed but no detectable PII — exposed_files already covers this
        return findings
    sev = "critical" if cc_candidates else "high"
    findings.append(Finding(
        severity=sev,
        title=f"/wp-content/debug.log contains personal data ({', '.join(findings_in_log)})",
        evidence=(
            f"Public-readable debug.log has identifiable content in the first 4 KB:\n"
            + (f"  - {len(emails)} email(s): {sorted(emails)[0][:5]}*** + others\n" if emails else "")
            + (f"  - {len(cc_candidates)} 13-19 digit string(s): {cc_candidates[0][:6]}***\n" if cc_candidates else "")
            + (f"  - {len(ips)} IP address(es)\n" if ips else "")
            + "\nA debug log with customer PII (emails) is a GDPR processing record "
              "that needs to be either secured or deleted; with card-shaped digit "
              "strings it's a PCI-DSS reportable incident."
        ),
        remediation=(
            "1. IMMEDIATELY: block /wp-content/debug.log at the web server "
            "(nginx: `location = /wp-content/debug.log { deny all; }`).\n"
            "2. Rotate the log somewhere outside the web root: in wp-config.php "
            "`define('WP_DEBUG_LOG', '/var/log/wp/debug.log');`.\n"
            "3. Set `define('WP_DEBUG_DISPLAY', false);` so errors never reach "
            "page bodies.\n"
            "4. Assess the leak scope: how many visitors could have downloaded "
            "the file in the exposure window. GDPR Article 34 notification may "
            "be required if individuals' rights are impacted."
        ),
        url=client.url("/wp-content/debug.log"),
        extra={"emails_found": len(emails), "cc_shaped": len(cc_candidates),
               "ips_found": len(ips)},
    ))
    return findings
