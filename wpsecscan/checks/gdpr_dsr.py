"""GDPR Data-Subject-Request (DSR) disclosure audit.

Probes common privacy-page URLs and looks for evidence the site advertises a
DSR / "right of access" / contact-the-DPO process. Under GDPR Art. 12-15, EU
sites MUST tell visitors how to exercise data rights — and many WP sites
quietly miss this.

Purely defensive: GET-only, no auth, no parameters.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

PRIVACY_PATHS = (
    "/privacy/", "/privacy-policy/", "/privacy-policy.html", "/legal/privacy/",
    "/datenschutz/", "/dsgvo/", "/gdpr/", "/protection-des-donnees/",
    "/data-protection/", "/policies/privacy/",
)

# Phrases (lowercased) that suggest the page mentions a DSR process.
DSR_PHRASES = (
    "data subject", "subject access", "right of access", "right to access",
    "data protection officer", "dpo", "request your data", "data request",
    "delete my data", "erasure", "right to be forgotten", "right to erasure",
    "portability", "rectification", "data privacy contact",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    reachable: list[tuple[str, str]] = []  # (path, body_lower_sample)
    for p in PRIVACY_PATHS:
        step(f"probing privacy page {p}...")
        r = await client.get(p)
        if r is None or r.status_code >= 400:
            continue
        body = (r.text or "")[:20000].lower()
        if not body:
            continue
        reachable.append((p, body))
        break  # first match is enough; many sites have several aliases

    if not reachable:
        findings.append(
            Finding(
                severity="low",
                title="No privacy / GDPR page found at the usual paths",
                evidence=f"Probed: {', '.join(PRIVACY_PATHS)}",
                remediation=(
                    "Publish a privacy notice at /privacy/ (or equivalent) that names the data controller, "
                    "the legal bases for processing, the retention periods, and HOW visitors can exercise "
                    "their rights (access, erasure, portability). Required by GDPR Art. 13-14 for any EU traffic."
                ),
                url=ctx["target"],
            )
        )
        return findings

    p, body = reachable[0]
    hits = [phr for phr in DSR_PHRASES if phr in body]
    if not hits:
        findings.append(
            Finding(
                severity="medium",
                title=f"Privacy page at {p} is missing a Data-Subject-Request process",
                evidence=(
                    f"Found a page at {p} but none of the expected DSR phrases appeared in the first 20 KB.\n"
                    "Phrases looked for: 'data subject', 'right of access', 'right to erasure', 'DPO', "
                    "'request your data', etc."
                ),
                remediation=(
                    "Add a section to the privacy page explaining how to request data access / deletion / "
                    "portability, with a contact email or web form. GDPR Art. 12 requires the process to be "
                    "'easily accessible and easy to understand'."
                ),
                url=client.url(p),
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"Privacy page at {p} mentions DSR concepts ({len(hits)} phrase(s) matched)",
                evidence=f"Matched phrases: {', '.join(sorted(hits)[:8])}",
                remediation="No immediate action — verify the page also has an actual contact channel for requests.",
                url=client.url(p),
            )
        )
    return findings
