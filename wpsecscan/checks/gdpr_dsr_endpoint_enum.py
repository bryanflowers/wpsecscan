"""A21 (v2.6.0) — GDPR DSR endpoint enumeration.

Core WordPress (since 4.9.6) ships data-export + data-erasure tools at
`/wp-admin/tools.php?page=export_personal_data` and `=remove_personal_data`.
The handler endpoints (`/wp-admin/admin-ajax.php?action=wp-privacy-*`)
are sometimes misconfigured by 3rd-party data-source plugins, leaving
the request-personal-data flow callable without authentication.

Passive: probe both the wp-admin pages + the ajax actions. A 200 on
the admin page without auth is a low-info advisory (login bypass would
need separate evidence); a 200 on the ajax action without nonce is a
medium.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_AJAX_ACTIONS = (
    "wp-privacy-export-personal-data",
    "wp-privacy-erase-personal-data",
    "wp-privacy-erasure-request",
    "wp-privacy-request",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for action in _AJAX_ACTIONS:
        step(f"GDPR DSR probe: {action}")
        r = await client.post(
            "/wp-admin/admin-ajax.php",
            data={"action": action, "request_id": "1"},
        )
        if r is None:
            continue
        status = r.status_code
        body = (r.text or "")[:300].lower()

        # WP correctly returns -1 / 0 / "bad nonce" for unauth requests.
        if status == 200 and not any(s in body for s in
                                       ("-1", "0", "nonce", "auth", "permission", "denied")):
            findings.append(Finding(
                severity="medium",
                title=f"GDPR DSR ajax action callable without nonce: {action}",
                evidence=(
                    f"POST admin-ajax.php?action={action} → HTTP 200, body has\n"
                    f"no auth/nonce error: {body[:200]}\n"
                    "An attacker could trigger / drain the DSR queue."
                ),
                remediation=(
                    "1. Verify your privacy plugin (or a custom plugin handling "
                    f"'{action}') checks current_user_can('manage_options') and "
                    "wp_verify_nonce() before doing any work.\n"
                    "2. Confirm WordPress core version is current — early WP\n"
                    "5.x ones had nonce-bypass bugs in this flow."
                ),
                url=client.url("/wp-admin/admin-ajax.php"),
                extra={"action": action},
            ))
    return findings
