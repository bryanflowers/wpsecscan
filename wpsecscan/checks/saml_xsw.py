"""SAML XML Signature Wrapping (XSW) probe.

If the site exposes a SAML SSO endpoint, test a tiny XSW variant: a SAML
response with an extra wrapped assertion. A vulnerable SP processes the
unsigned assertion's claims while validating the SIGNED inner assertion —
classic SSO auth bypass.

This is a low-aggressiveness PASSIVE probe: we only LOOK for SAML endpoints
and serve known-good error responses. The actual XSW payload tests are
deferred to an active extension (out of scope for the passive check).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

SAML_PATHS = (
    "/saml/", "/saml/acs", "/saml/sso", "/wp-saml-auth",
    "/wp-content/plugins/wp-saml-auth/", "/auth/saml/",
    "/simplesamlphp/", "/Shibboleth.sso/", "/sp/SAML2/Redirect/Login",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    reachable: list[tuple[str, int]] = []
    for path in SAML_PATHS:
        step(f"probing SAML endpoint {path}...")
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code in (200, 302, 405) and r.content:
            body_lc = (r.text or "")[:5000].lower()
            if any(m in body_lc for m in ("saml", "shibboleth", "assertionconsumer", "audience restriction")):
                reachable.append((path, r.status_code))

    if not reachable:
        findings.append(
            Finding(
                severity="info",
                title="No SAML SSO endpoints reachable",
                evidence=f"Probed {len(SAML_PATHS)} common SAML paths; none indicated a SAML-Service-Provider implementation.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    findings.append(
        Finding(
            severity="medium",
            title="SAML SSO endpoint(s) detected — XSW testing recommended",
            evidence=(
                "Reachable SAML endpoints:\n"
                + "\n".join(f"  - {p} (HTTP {c})" for p, c in reachable)
                + "\n\n"
                "SAML Service Providers have a long history of XSW (XML Signature Wrapping) bugs where the SP "
                "validates ONE assertion's signature but processes a DIFFERENT, unsigned assertion's claims. "
                "wpsecscan's passive check identifies the SAML endpoint; XSW exploitation requires interactive "
                "testing with tools like SAMLRaider (Burp extension) or python3-saml's vulnerability checklist."
            ),
            remediation=(
                "1. Confirm your SAML library is current (python3-saml 1.16+, simplesamlphp 2.0+, Shibboleth SP 3.2+).\n"
                "2. Verify the SP rejects responses where the signature covers a different element than the asserted claims.\n"
                "3. Manual test: SAMLRaider in Burp Suite has automated XSW payload generation; run it against your IdP test flow."
            ),
            url=client.url(reachable[0][0]),
        )
    )
    return findings
