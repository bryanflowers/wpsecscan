"""OAuth / login redirect-URI validation probe.

WordPress's wp-login.php and several OAuth plugins accept a `redirect_to` /
`redirect_uri` parameter and bounce the user to that URL after login. Sites
that don't restrict the destination to same-origin URLs let attackers craft
phishing links where the URL bar shows YOUR domain.

Probe: send a redirect URL that points to evil.example.com and check whether
the resulting Location header (or HTML meta refresh) points to the attacker.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

EVIL_HOST = "wpsecscan-evil.example.com"
EVIL_URL = f"https://{EVIL_HOST}/phished"

PROBE_TEMPLATES = (
    # WordPress core wp-login.php redirect_to
    ("/wp-login.php", {"redirect_to": EVIL_URL}, "redirect_to"),
    # Common plugin: WP OAuth Server
    ("/oauth/authorize", {"redirect_uri": EVIL_URL, "client_id": "test", "response_type": "code"}, "redirect_uri"),
    # WP REST: app-passwords authorize flow
    ("/wp-admin/authorize-application.php", {"success_url": EVIL_URL, "app_name": "wpsec-test"}, "success_url"),
    # Common plugin: WP OAuth2 Server
    ("/wp-json/oauth2/authorize", {"redirect_uri": EVIL_URL, "client_id": "test"}, "redirect_uri"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    leaks: list[tuple[str, str, str]] = []  # (path, param, location_header)
    for path, params, param_name in PROBE_TEMPLATES:
        step(f"probing {path} for unrestricted {param_name}...")
        r = await client.get(path, params=params)
        if r is None:
            continue
        if r.status_code in (301, 302, 303, 307, 308):
            loc = (r.headers.get("location") or r.headers.get("Location") or "")
            if EVIL_HOST in loc:
                leaks.append((path, param_name, loc[:160]))
                continue
        # Some plugins use meta-refresh instead of HTTP redirect
        body = (r.text or "")[:8000]
        if "http-equiv=\"refresh\"" in body.lower() and EVIL_HOST in body:
            leaks.append((path, param_name, "meta-refresh in body"))

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="No unrestricted OAuth / login redirect found",
                evidence=f"Probed {len(PROBE_TEMPLATES)} known OAuth/login redirect params with an external URL.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for path, param, loc in leaks:
        findings.append(
            Finding(
                severity="high",
                title=f"Unrestricted {param} at {path} — phishing-link primitive",
                evidence=(
                    f"GET {path}?{param}={EVIL_URL} -> Location: {loc}\n\n"
                    "An attacker can craft a URL on YOUR domain that, when clicked, lands the "
                    "victim on an attacker-controlled page (after a login flow that looks normal)."
                ),
                remediation=(
                    "Validate the redirect target against an allow-list of same-origin paths. "
                    "For wp-login.php specifically, the `wp_safe_redirect()` core function does "
                    "this — verify the plugin owning this endpoint uses it. Reference: "
                    "https://developer.wordpress.org/reference/functions/wp_safe_redirect/"
                ),
                url=client.url(path),
            )
        )
    return findings
