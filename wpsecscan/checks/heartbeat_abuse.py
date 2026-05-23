"""#7 WordPress Heartbeat API abuse / DoS probe.

`/wp-admin/admin-ajax.php?action=heartbeat` is the autosave heartbeat
endpoint. On many WP setups it accepts unauthenticated POSTs with arbitrary
`data[]` keys and does substantial DB work per request. An attacker can
hammer it to drive load.
"""
from __future__ import annotations

import time
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("heartbeat: timing 3 unauth POSTs...")
    times: list[float] = []
    statuses: list[int] = []
    for _ in range(3):
        t0 = time.perf_counter()
        r = await client.request("POST", "/wp-admin/admin-ajax.php",
                                  data={"action": "heartbeat", "_nonce": ""},
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        times.append(time.perf_counter() - t0)
        if r is not None:
            statuses.append(r.status_code)
    if not statuses:
        return [Finding(severity="info", title="Heartbeat probe unreachable",
                        evidence="No response.", remediation="No action.", url=ctx["target"])]
    avg_ms = (sum(times) / len(times)) * 1000
    sev = "medium" if (200 in statuses and avg_ms > 250) else "info"
    title = (f"Heartbeat: unauth POST avg {avg_ms:.0f} ms (DoS-amplification risk)"
             if sev == "medium"
             else f"Heartbeat: unauth POST returns {statuses[0]} ({avg_ms:.0f} ms avg)")
    return [Finding(
        severity=sev,
        title=title,
        evidence=f"3 unauth POSTs returned status {statuses}, avg {avg_ms:.0f} ms.\nAttackers can amplify this with a tight loop.",
        remediation="Install the 'Heartbeat Control' plugin OR add: `add_action('init', function(){ if (!is_user_logged_in()) wp_deregister_script('heartbeat'); });`. Belt-and-braces: rate-limit `/wp-admin/admin-ajax.php` at the WAF level.",
        url=ctx["target"] + "/wp-admin/admin-ajax.php",
    )]
