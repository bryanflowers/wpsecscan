"""WordPress Application Passwords audit.

Since WP 5.6, Application Passwords are a built-in way for clients to
authenticate to the REST API without using the user password. They're great
for legitimate integrations and a constant target for attackers because:
  - The endpoint /wp-json/wp/v2/users/me?context=edit returns 401 with a
    WWW-Authenticate header that reveals whether Application Passwords are on.
  - The /wp-admin/profile.php?page=application-passwords surface is the
    creation flow.

This check looks for:
  - Whether the Application Passwords feature is enabled (info)
  - Whether the authorization endpoint at /wp-admin/authorize-application.php
    is reachable (info)
  - Whether the JWT alternative plugin is installed
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Application Passwords feature endpoint
    step("checking Application Passwords feature endpoint...")
    r = await client.get("/wp-json/wp/v2/users/me", headers={"Authorization": "Basic d3JvbmdAd3JvbmcudGxkOnpvb20="})
    if r is not None:
        www_auth = r.headers.get("www-authenticate", "") or r.headers.get("WWW-Authenticate", "")
        if "application password" in (www_auth or "").lower() or r.status_code == 401:
            findings.append(
                Finding(
                    severity="info",
                    title="WordPress Application Passwords feature is enabled",
                    evidence=(
                        f"GET /wp-json/wp/v2/users/me with a fake Basic auth -> HTTP {r.status_code}\n"
                        f"  WWW-Authenticate: {www_auth or '(not present)'}\n"
                        "Application Passwords are how the REST API authenticates non-cookie clients (5.6+).\n"
                        "Built-in feature; on by default unless explicitly disabled."
                    ),
                    remediation=(
                        "If you don't integrate any external services with WordPress, disable Application Passwords:\n"
                        "  add_filter('wp_is_application_passwords_available', '__return_false');\n"
                        "If you do use them, audit /wp-admin/profile.php under each admin's profile for unrecognized entries."
                    ),
                    url=client.url("/wp-json/wp/v2/users/me"),
                )
            )

    # Authorize endpoint
    step("checking /wp-admin/authorize-application.php reachability...")
    r = await client.get("/wp-admin/authorize-application.php", follow_redirects=False)
    if r is not None and r.status_code in (200, 302):
        findings.append(
            Finding(
                severity="low",
                title="Application Password authorize endpoint is reachable",
                evidence=(
                    f"GET /wp-admin/authorize-application.php -> {r.status_code}\n"
                    "This is the OAuth-style consent screen for issuing Application Passwords. "
                    "An attacker with a phishing pretext can social-engineer an admin into authorizing a malicious client."
                ),
                remediation=(
                    "Restrict the endpoint to a known set of IPs or behind an auth gate if not actively used. "
                    "Educate admins to NEVER click 'Authorize' links they didn't initiate themselves."
                ),
                url=client.url("/wp-admin/authorize-application.php"),
            )
        )

    # JWT Authentication for WP REST API plugin probe
    step("checking JWT authentication plugin...")
    r = await client.get("/wp-json/jwt-auth/v1/token", follow_redirects=False)
    if r is not None and r.status_code in (200, 405, 400):
        findings.append(
            Finding(
                severity="info",
                title="JWT Authentication for WP REST API plugin is installed",
                evidence=(
                    f"GET /wp-json/jwt-auth/v1/token -> HTTP {r.status_code}\n"
                    "The 'JWT Authentication for WP REST API' plugin is in active use. "
                    "Several historical CVEs (e.g. CVE-2024-1631) — keep it updated."
                ),
                remediation=(
                    "Make sure the JWT-Auth plugin is on its latest release (≥1.3.7). "
                    "Confirm JWT_AUTH_SECRET_KEY is set to a strong random value in wp-config.php."
                ),
                url=client.url("/wp-json/jwt-auth/v1/token"),
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Application Passwords / JWT auth not detected",
                evidence="No matching WWW-Authenticate header, /wp-admin/authorize-application.php returned non-2xx, no jwt-auth namespace.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings
