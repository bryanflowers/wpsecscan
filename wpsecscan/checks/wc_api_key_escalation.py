"""A28 (v2.6.0) — WooCommerce REST API key scope-escalation audit.

WooCommerce REST API keys (consumer_key + consumer_secret) come in 3
scopes: read, write, read_write. When a key with `read_write` scope is
used, several historical bugs let the same Basic Auth hit non-WC
endpoints — including `/wp-json/wp/v2/users/me/application-passwords/
introspect` which leaks the user's app-password fingerprints.

Passive: probe `/wp-json/wp/v2/users/me/application-passwords` with
NO auth + check the WWW-Authenticate header for "application password"
hint. The presence of that hint, combined with the existence of
`/wp-json/wc/v3/system_status`, suggests WC and WP-API live on the
same auth surface — the operator should audit their API-key scope.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("WC API key scope advisory: probe wp + wc surfaces")
    wp = await client.get("/wp-json/wp/v2/users/me/application-passwords")
    wc = await client.get("/wp-json/wc/v3/system_status")

    if wp is None or wc is None:
        return findings
    if wp.status_code in (401, 403) and wc.status_code in (401, 403, 200):
        # Both endpoints present (WP REST + WC REST) — give the advisory.
        findings.append(Finding(
            severity="low",
            title="WP REST + WooCommerce REST both present — verify API-key scope is read-only",
            evidence=(
                "Both `/wp-json/wp/v2/users/me/application-passwords` and\n"
                "`/wp-json/wc/v3/system_status` are reachable on this install.\n"
                "WC API keys with `read_write` scope have historically been\n"
                "usable against non-WC WP REST endpoints when Basic Auth is\n"
                "accepted at both layers."
            ),
            remediation=(
                "1. Audit WooCommerce → Settings → Advanced → REST API → Keys.\n"
                "2. Every integration key should be `read` scope unless write\n"
                "   is genuinely required.\n"
                "3. Move write-scope integrations to Application Passwords\n"
                "   with capability-restricted users instead.\n"
                "4. Rotate any key whose scope you can't justify."
            ),
            url=client.url("/wp-json/wc/v3/system_status"),
            extra={"wp_status": wp.status_code, "wc_status": wc.status_code},
        ))
    return findings
