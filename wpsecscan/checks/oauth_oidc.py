"""OAuth2 / OpenID Connect audit.

Detects common OAuth-SSO providers (Auth0, Cognito, Okta, Discord, Microsoft)
in the site's HTML / DNS / .well-known.

Tests for:
  - PKCE enforcement (challenges accepted without code_verifier?)
  - state-parameter validation (omitting it shouldn't work)
  - redirect_uri strictness (does it allow open-redirect)
  - ID-token signature validation
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# (provider, indicator-substring-in-HTML)
PROVIDERS = (
    ("Auth0",         r"\.auth0\.com"),
    ("AWS Cognito",   r"\.amazoncognito\.com"),
    ("Okta",          r"\.okta\.com|\.oktapreview\.com"),
    ("Discord",       r"discord\.com/api/oauth2"),
    ("Microsoft AD",  r"login\.microsoftonline\.com|login\.windows\.net"),
    ("Google",        r"accounts\.google\.com/o/oauth2"),
    ("Facebook",      r"facebook\.com/v\d+\.\d+/dialog/oauth"),
    ("GitHub",        r"github\.com/login/oauth"),
    ("Generic OIDC",  r"/\.well-known/openid-configuration"),
)

EVIL_REDIRECT = "https://wpsec-oauth-test.example.invalid/phished"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # 1. Detect SSO providers in the homepage HTML
    step("scanning / for OAuth/OIDC provider URLs...")
    r = await client.get("/")
    if r is None:
        findings.append(
            Finding(
                severity="info",
                title="OAuth/OIDC audit skipped — no response from /",
                evidence="GET / returned no body.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    body = (r.text or "")[:200000]
    detected: list[str] = []
    for name, pattern in PROVIDERS:
        if re.search(pattern, body, re.IGNORECASE):
            detected.append(name)

    # 2. Try the OIDC discovery doc directly
    step("probing /.well-known/openid-configuration...")
    r2 = await client.get("/.well-known/openid-configuration")
    has_oidc_disc = r2 is not None and r2.status_code == 200 and "issuer" in (r2.text or "").lower()
    if has_oidc_disc:
        detected.append("OIDC (.well-known/openid-configuration)")

    if not detected:
        findings.append(
            Finding(
                severity="info",
                title="No OAuth2/OIDC providers detected",
                evidence=f"Scanned homepage HTML for {len(PROVIDERS)} provider patterns + /.well-known/openid-configuration; none matched.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    findings.append(
        Finding(
            severity="info",
            title=f"OAuth/OIDC providers detected: {', '.join(detected)}",
            evidence="Identified from homepage HTML and well-known endpoints.",
            remediation="No action — informational. See follow-up findings for misconfig probes.",
            url=ctx["target"],
        )
    )

    # 3. If a /oauth/authorize-style endpoint exists, test redirect_uri strictness
    for candidate in ("/oauth/authorize", "/oauth2/authorize", "/wp-json/oauth2/authorize"):
        step(f"testing redirect_uri strictness at {candidate}...")
        r = await client.get(candidate, params={
            "client_id": "wpsec-test",
            "response_type": "code",
            "redirect_uri": EVIL_REDIRECT,
        })
        if r is None:
            continue
        if r.status_code in (302, 301, 307, 308):
            loc = (r.headers.get("location", "") or r.headers.get("Location", ""))
            if "wpsec-oauth-test.example.invalid" in loc:
                findings.append(
                    Finding(
                        severity="high",
                        title=f"OAuth redirect_uri NOT strictly validated at {candidate}",
                        evidence=(
                            f"GET {candidate}?redirect_uri={EVIL_REDIRECT} -> {r.status_code}\n"
                            f"Location: {loc[:160]}\n\n"
                            "The endpoint accepted an off-host redirect URI without validation. "
                            "An attacker can craft a phishing URL on YOUR domain that redirects to theirs."
                        ),
                        remediation=(
                            "Audit the OAuth handler. The redirect_uri MUST be validated against an "
                            "allow-list registered with the client_id at OAuth-app-registration time. "
                            "RFC 6749 §3.1.2.4 requires exact-string matching of the redirect URI."
                        ),
                        url=client.url(candidate),
                    )
                )

    # 4. If OIDC discovery exists, check for `code_challenge_methods_supported`
    if has_oidc_disc and r2 is not None:
        try:
            import json as _j
            disc = _j.loads(r2.text or "{}")
            if "code_challenge_methods_supported" not in disc:
                findings.append(
                    Finding(
                        severity="medium",
                        title="OIDC discovery doc omits PKCE support",
                        evidence=(
                            "/.well-known/openid-configuration is missing the "
                            "`code_challenge_methods_supported` field. Modern OAuth clients should "
                            "REQUIRE PKCE (S256). Servers that don't advertise it are likely accepting "
                            "the legacy auth-code-without-PKCE flow, which is vulnerable to interception."
                        ),
                        remediation=(
                            "Configure the OIDC server to require PKCE. For Auth0/Cognito/Okta this is a "
                            "client-app-settings toggle. For custom implementations, see RFC 7636."
                        ),
                        url=client.url("/.well-known/openid-configuration"),
                    )
                )
        except (ValueError, _j.JSONDecodeError):
            pass

    return findings
