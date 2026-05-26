"""Detect DISABLE_WP_CRON without confirmed external replacement.

If wp-cron.php returns 403/redirect-to-login rather than the empty 200
WordPress normally serves, DISABLE_WP_CRON is likely set. That's good for
performance — but ONLY if a real cron job (or a host-managed scheduler)
replaces it. Without a replacement, scheduled events (digest emails, post
publication, plugin upkeep, transient cleanup) silently stop firing.
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("probing /wp-cron.php for DISABLE_WP_CRON indicators...")
    r = await client.get("/wp-cron.php")
    if r is None:
        return findings
    # Normal: HTTP 200 with empty body (or X-WP-Cron header).
    # DISABLE_WP_CRON likely: 403, or redirect away from wp-cron.php.
    suspicious = False
    why = ""
    if r.status_code == 403:
        suspicious = True
        why = "403 Forbidden"
    elif r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "")
        if "wp-cron.php" not in loc.lower():
            suspicious = True
            why = f"redirected to {loc[:120]}"
    if not suspicious:
        return findings  # No signal either way; skip silently.
    # Look for X-WP-Cron header that would confirm replacement scheduler.
    has_replacement_header = bool(r.headers.get("X-WP-Cron") or r.headers.get("x-wp-cron"))
    if has_replacement_header:
        findings.append(Finding(
            severity="info",
            title="DISABLE_WP_CRON likely set, X-WP-Cron header confirms replacement",
            evidence=f"/wp-cron.php → {why}. X-WP-Cron header present — replacement scheduler is active.",
            remediation="No action.",
            url=client.url("/wp-cron.php"),
        ))
        return findings
    findings.append(Finding(
        severity="info",
        title=f"DISABLE_WP_CRON may be set, no confirmation of replacement scheduler",
        evidence=(
            f"/wp-cron.php → {why}. This suggests DISABLE_WP_CRON is true in "
            "wp-config.php. WordPress's scheduled events (digests, transients, "
            "post publication, plugin tasks) will NOT fire unless a real cron job "
            "or host-managed scheduler hits wp-cron.php periodically. We can't "
            "verify that externally."
        ),
        remediation=(
            "If you intentionally disabled wp-cron, confirm the replacement is "
            "running. Typical replacements:\n"
            "  - cron:  */15 * * * * curl -s https://YOURSITE/wp-cron.php?doing_wp_cron > /dev/null\n"
            "  - systemd timer or Windows Task Scheduler at the same cadence\n"
            "  - hosts like WP Engine / Kinsta run a managed cron — check the panel\n"
            "If no replacement is set, scheduled events are silently broken."
        ),
        url=client.url("/wp-cron.php"),
    ))
    return findings
