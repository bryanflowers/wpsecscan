"""A22 (v2.6.0) — POST /wp-json/wp/v2/plugins race / slug-validation probe.

WordPress core REST endpoint `POST /wp-json/wp/v2/plugins` accepts a
`slug` parameter and installs the matching plugin from the .org
repository. The slug is validated, but multiple CVEs in the 2024-2025
window allowed:

  • Bypass of the slug regex via URL-encoded path-traversal patterns.
  • Race condition where parallel POSTs with conflicting slugs let one
    install an arbitrary slug before validation completed.

The endpoint requires `install_plugins` capability — passive probe
just confirms auth IS enforced (we don't try the race, which would
actually install plugins).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("plugin install REST probe (unauthenticated)")
    r = await client.post(
        "/wp-json/wp/v2/plugins",
        json={"slug": "wpsecscan-probe-not-real"},
    )
    if r is None:
        return findings

    status = r.status_code
    if status in (401, 403):
        # Hardened — expected response.
        findings.append(Finding(
            severity="info",
            title="REST plugin-install endpoint properly auth-gated",
            evidence=f"POST /wp-json/wp/v2/plugins → HTTP {status} (auth required).",
            remediation=(
                "Endpoint is correctly gated. Confirm:\n"
                "  - WordPress core >= 6.5 (patched slug-regex bypass)\n"
                "  - DISALLOW_FILE_MODS or FS_METHOD restrictions are in place\n"
                "    in wp-config.php if installs should be admin-only-via-SSH."
            ),
            url=client.url("/wp-json/wp/v2/plugins"),
            extra={"status": status},
        ))
    elif status in (200, 201, 202):
        # Unauthenticated install succeeded — critical
        findings.append(Finding(
            severity="critical",
            title="REST plugin-install endpoint accepts unauthenticated POST",
            evidence=(
                f"POST /wp-json/wp/v2/plugins {{'slug':'...'}} → HTTP {status}.\n"
                f"Body: {(r.text or '')[:200]}\n"
                "An attacker can install ANY plugin from the .org repo. "
                "Combined with a vulnerable plugin upload, this is RCE."
            ),
            remediation=(
                "1. IMMEDIATE: set define('DISALLOW_FILE_MODS', true); in\n"
                "   wp-config.php to disable all plugin installs over HTTP.\n"
                "2. Audit which plugin removed the permission callback (likely\n"
                "   a custom plugin overrode rest_authentication_errors).\n"
                "3. Re-install WordPress core after rotating SECRET_* keys."
            ),
            url=client.url("/wp-json/wp/v2/plugins"),
            extra={"status": status},
        ))
    return findings
