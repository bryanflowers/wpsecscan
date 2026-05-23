"""#35 cache poisoning chain v2 — full poison-then-victim chain.

Sends two requests:
  1. Poison: GET / with X-Forwarded-Host: evil.example.com (asks cache to
     store a response whose internal links point at evil.example.com)
  2. Victim: GET / with a normal Host header — if the response contains
     evil.example.com, the cache served the poisoned copy.

Aggressive only.
"""
from __future__ import annotations

import asyncio
from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    if not ctx.get("aggressive"):
        return [Finding(severity="info", title="Cache-poisoning v2 skipped (passive)",
                        evidence="Pass --aggressive.", remediation="No action.", url=ctx["target"])]
    step = ctx.get("step") or (lambda _s: None)
    step("cache-poison v2: phase 1 (poison)...")
    poison_marker = "wpsecscan-poison-marker.invalid"
    await client.get("/", headers={"X-Forwarded-Host": poison_marker,
                                    "X-Forwarded-Proto": "http"})
    await asyncio.sleep(0.5)
    step("cache-poison v2: phase 2 (victim)...")
    r = await client.get("/")
    if r is None:
        return [Finding(severity="info", title="Cache-poisoning v2 — victim fetch failed",
                        evidence="Could not retrieve /.", remediation="No action.", url=ctx["target"])]
    body = (r.text or "")[:200_000]
    if poison_marker in body:
        return [Finding(
            severity="critical",
            title="Cache poisoned via X-Forwarded-Host → next visitor served attacker host",
            evidence=f"Phase 1 (poison): X-Forwarded-Host: {poison_marker} → cached.\nPhase 2 (victim, no header): response contained `{poison_marker}`.\n\nAttackers can redirect every cache-hit visitor to an arbitrary host.",
            remediation=("1. Strip X-Forwarded-* / X-Host / Forwarded headers at the CDN edge.\n"
                        "2. Configure the application to use a hard-coded `WP_SITEURL` rather than `$_SERVER['HTTP_HOST']`.\n"
                        "3. Have the CDN include the rewritten host in the cache key, OR add Vary: X-Forwarded-Host to all responses."),
            url=ctx["target"],
        )]
    return [Finding(severity="info", title="Cache-poisoning v2 — no marker in victim response",
                    evidence="The X-Forwarded-Host poison marker didn't reach the next visitor.",
                    remediation="No action.", url=ctx["target"])]
