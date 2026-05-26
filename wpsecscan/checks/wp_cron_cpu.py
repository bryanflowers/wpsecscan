"""wp-cron.php per-request CPU/wall-time measurement.

Existing `wp_cron_dos.py` flags wp-cron exposure. This adds a concrete
amplification arithmetic: time two sequential GETs to wp-cron.php and
compute response time. If wp-cron consistently takes > 2s, a low-rate
DoS becomes very cheap (20 req/s saturates a 1-vCPU host).
"""
from __future__ import annotations
import time
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    timings: list[float] = []
    for i in range(2):
        step(f"timing /wp-cron.php request {i+1}/2 (cold)...")
        t0 = time.perf_counter()
        r = await client.get("/wp-cron.php")
        dt = time.perf_counter() - t0
        if r is None or r.status_code in (403, 404):
            return findings  # endpoint not reachable
        timings.append(dt)
    avg_ms = sum(timings) / len(timings) * 1000
    if avg_ms < 800:
        findings.append(Finding(
            severity="info",
            title=f"wp-cron.php responds in ~{avg_ms:.0f} ms — within tolerance",
            evidence=f"Avg of 2 cold requests: {avg_ms:.0f} ms.",
            remediation="No action.",
            url=client.url("/wp-cron.php"),
        ))
        return findings
    # Compute concrete amplification
    sev = "medium" if avg_ms < 2000 else "high"
    sat_rps = 1000 / avg_ms * 10  # rough: 10 concurrent connections per vCPU
    findings.append(Finding(
        severity=sev,
        title=f"wp-cron.php is slow: ~{avg_ms:.0f} ms/request — cheap DoS amplification",
        evidence=(
            f"Two cold requests to /wp-cron.php averaged {avg_ms:.0f} ms.\n"
            f"Each wp-cron hit triggers every scheduled task synchronously, "
            "so visitor-driven scheduling (without DISABLE_WP_CRON) makes the "
            "site share its compute budget with random external pingers.\n\n"
            f"Concrete attack math: at {avg_ms:.0f} ms per request, an attacker "
            f"sending ~{sat_rps:.0f} req/s to /wp-cron.php saturates a "
            "1-vCPU host with no auth required and no payload — just hitting "
            "a public URL repeatedly."
        ),
        remediation=(
            "1. Set `define('DISABLE_WP_CRON', true);` in wp-config.php and "
            "register a real cron (or systemd timer / host-managed scheduler) "
            "that calls /wp-cron.php?doing_wp_cron once every 5-15 minutes.\n"
            "2. Block direct /wp-cron.php access from the public internet — "
            "e.g. nginx `location = /wp-cron.php { deny all; allow 127.0.0.1; }`\n"
            "3. Audit which plugin is making wp-cron slow — usually a sync "
            "remote API call from a daily/hourly hook."
        ),
        url=client.url("/wp-cron.php"),
        extra={"avg_response_ms": round(avg_ms)},
    ))
    return findings
