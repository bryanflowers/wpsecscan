"""WP REST application-passwords enumeration probe.

Round-64 #62 — WordPress 5.6+ supports Application Passwords. The REST
route `/wp/v2/users/me/application-passwords` lists active app-passwords
for the authenticated user; if exposed without auth (misconfigured
permission_callback in a plugin that re-registers the route), an
attacker gets the password names + UUIDs (not the secret) which is
already enough to fingerprint third-party integrations.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

_PROBE_PATHS = (
    "/wp-json/wp/v2/users/me/application-passwords",
    "/wp-json/wp/v2/users/1/application-passwords",
    "/wp-json/wp/v2/applications",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None:
            continue
        # Expected: 401 with rest_not_logged_in OR 403; if 200, that's bad
        if r.status_code == 200:
            body = (r.text or "")[:200]
            findings.append(
                Finding(
                    severity="high",
                    title=f"Application Passwords endpoint reachable unauthenticated: {path}",
                    evidence=f"GET {path} -> 200\n  Body (first 200 chars): {body!r}",
                    remediation=(
                        "WP-core requires authentication for this endpoint. A 200 indicates a plugin has registered a permission_callback returning true.\n"
                        "Audit your plugins for re-registration of /users/me/application-passwords. Specifically check any plugin that customises REST permissions.\n"
                        "Application Passwords can be disabled site-wide if unused:\n"
                        "  add_filter('wp_is_application_passwords_available', '__return_false');"
                    ),
                    url=client.url(path),
                )
            )
        # 401 = expected; record as info on the first path only
        elif r.status_code == 401 and path == _PROBE_PATHS[0]:
            findings.append(
                Finding(
                    severity="info",
                    title="Application Passwords endpoint properly requires auth",
                    evidence=f"GET {path} -> 401 (expected)",
                    remediation="No action needed. Ensure Application Passwords are rotated if any 3rd-party integration is decommissioned.",
                    url=client.url(path),
                )
            )

    return findings
