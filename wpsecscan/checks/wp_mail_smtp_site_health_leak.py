"""A26 (v2.6.0) — WP Mail SMTP key leak via Site Health debug dump.

Newer WP cores (6.5+) include Site Health debug info that can leak the
SMTP password unmasked when the WP Mail SMTP plugin is misconfigured.
The endpoint `/wp-admin/site-health.php?tab=debug` requires auth, but
some themes/plugins ship a public version (e.g. health-check helper
plugin's debug-info endpoint).

Passive: probe a few canonical site-health debug endpoints + flag
medium when they're reachable without auth.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PROBES = (
    "/wp-admin/site-health.php?tab=debug",
    "/wp-json/wp-site-health/v1/debug-data",
    "/wp-json/health-check/v1/debug",
    "/?health-check-debug",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBES:
        step(f"site-health debug probe: {path}")
        r = await client.get(path)
        if r is None or r.status_code not in (200, 401, 403):
            continue
        body = (r.text or "")[:600].lower()

        if r.status_code == 200 and any(s in body for s in
                                          ("smtp", "mail", "from", "host:", "debug")):
            findings.append(Finding(
                severity="high",
                title=f"Site Health debug dump reachable unauthenticated: {path}",
                evidence=(
                    f"GET {path} → HTTP 200\n"
                    "Debug dumps typically include SMTP host/port/user (and on\n"
                    "buggy WP Mail SMTP versions, the password in cleartext).\n"
                    f"Body excerpt: {body[:300]}"
                ),
                remediation=(
                    "1. Block " + path + " at the WAF until verified.\n"
                    "2. Confirm WP Mail SMTP plugin is current (mask-password\n"
                    "   bug was fixed in 4.4.x).\n"
                    "3. ROTATE the SMTP password immediately."
                ),
                url=client.url(path),
                extra={"path": path},
            ))
    return findings
