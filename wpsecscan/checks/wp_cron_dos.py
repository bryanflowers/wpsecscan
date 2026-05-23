"""#2 wp-cron.php DoS-amplification check.

`wp-cron.php` runs WordPress's scheduled-task system. Each web visit can
trigger it. If the site doesn't set `DISABLE_WP_CRON` + use system cron,
EVERY page-view that touches wp-cron costs the server N database queries
+ all the cron callbacks. An attacker can hit wp-cron.php in a loop.

We probe wp-cron.php directly (no DOING_CRON header) and time the response.
"""
from __future__ import annotations

import time
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("timing wp-cron.php (3 samples)...")
    times = []
    for _ in range(3):
        t0 = time.perf_counter()
        r = await client.get("/wp-cron.php")
        elapsed = time.perf_counter() - t0
        if r is None:
            continue
        times.append((elapsed, r.status_code, len(r.content or b"")))
    if not times:
        return [Finding(severity="info", title="wp-cron.php unreachable",
                        evidence="No response on /wp-cron.php.", remediation="No action.",
                        url=ctx["target"])]
    avg = sum(t[0] for t in times) / len(times)
    findings = []
    if avg > 0.8:
        findings.append(Finding(
            severity="medium",
            title=f"wp-cron.php DoS amplification — avg {avg*1000:.0f} ms per hit",
            evidence=f"3 sample hits to /wp-cron.php averaged {avg*1000:.0f} ms · responses: {[(int(t[0]*1000), t[1]) for t in times]}\n\nA loop of 100 req/s against this endpoint would consume ~{avg*100:.0f} CPU-seconds/s — easy to overwhelm.",
            remediation="Set `define('DISABLE_WP_CRON', true);` in wp-config.php, then schedule `php /path/wp-cron.php` via system cron (every 5min). Optionally `location = /wp-cron.php { deny all; }` once system cron handles it.",
            url=ctx["target"] + "/wp-cron.php",
        ))
    else:
        findings.append(Finding(
            severity="info",
            title=f"wp-cron.php responds in ~{avg*1000:.0f} ms (no amplification observed)",
            evidence=f"Sample times: {[int(t[0]*1000) for t in times]} ms",
            remediation="No action.", url=ctx["target"],
        ))
    return findings
