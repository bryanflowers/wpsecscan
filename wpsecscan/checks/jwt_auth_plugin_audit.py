"""A17 (v2.6.0) — `jwt-authentication-for-wp-rest-api` plugin audit.

The popular Tmeister/Useful Team `jwt-authentication-for-wp-rest-api`
plugin had multiple CVEs around the JWT secret being:

  • Read from a constant (`define('JWT_AUTH_SECRET_KEY', '...')`) that
    devs frequently leave as the placeholder string or commit to repos.
  • Accepted from a query parameter in older versions.
  • Reusable across token-revocation events.

Passive: probe the plugin's canonical token endpoint
(`/wp-json/jwt-auth/v1/token`) and look for the secret-not-set error
message ("JWT is not configurated properly, please contact the
admin"), which means anyone can craft an unsigned token that the
plugin will accept.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_ENDPOINT = "/wp-json/jwt-auth/v1/token"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step(f"JWT-Auth probe: POST {_ENDPOINT}")
    r = await client.post(
        _ENDPOINT,
        data={"username": "wpsecscan-probe", "password": "wpsecscan-probe"},
    )
    if r is None or r.status_code == 404:
        return findings

    body = (r.text or "").lower()

    # The plugin returns this specific error when JWT_AUTH_SECRET_KEY isn't
    # set in wp-config.php — meaning ANY token validates.
    if "not configurated" in body or "secret_key" in body or "jwt_auth_secret" in body:
        findings.append(Finding(
            severity="critical",
            title="JWT-Auth plugin reports SECRET_KEY missing — anyone can forge admin tokens",
            evidence=(
                f"POST {_ENDPOINT} → HTTP {r.status_code}\n"
                f"Body: {body[:300]}\n"
                "The plugin's secret key isn't configured; it falls back to a "
                "default-empty secret and accepts any HS256-signed token."
            ),
            remediation=(
                "1. IMMEDIATE: deactivate the plugin until the secret is set.\n"
                "2. In wp-config.php, add a strong random secret:\n"
                "   define('JWT_AUTH_SECRET_KEY', '<64-char-random>');\n"
                "3. Generate via: `openssl rand -base64 48`.\n"
                "4. Reactivate. Audit recent admin actions for forged tokens."
            ),
            url=client.url(_ENDPOINT),
            extra={"category": "jwt-secret-missing"},
        ))
        return findings

    # 401 with proper error message is the expected hardened response.
    if r.status_code in (401, 403):
        findings.append(Finding(
            severity="info",
            title="JWT-Auth plugin present + secret configured (probe rejected as expected)",
            evidence=f"POST {_ENDPOINT} → HTTP {r.status_code}; plugin is hardened.",
            remediation=(
                "Plugin is correctly configured. Rotate JWT_AUTH_SECRET_KEY "
                "every 90 days; revoke all issued tokens on rotation."
            ),
            url=client.url(_ENDPOINT),
            extra={"status": r.status_code},
        ))
    return findings
