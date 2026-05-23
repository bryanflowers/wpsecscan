"""admin-ajax brute-force surface check.

NOT a brute-force tool. We just probe whether `/wp-admin/admin-ajax.php`
applies rate-limiting to authenticated-only actions when called without
auth. We send 5 deliberately-wrong calls to a known authenticated action
(`wp-link-ajax`) and confirm:
  - That the endpoint responds (good)
  - That repeated calls don't get throttled (concerning — would let
    attackers brute-force authentication signals via this endpoint)

This complements login_throttle; admin-ajax is often forgotten.
"""
from __future__ import annotations

import asyncio

from ..http import Client
from ..models import Finding

ATTEMPTS = 5
assert ATTEMPTS <= 5
PACING_SECONDS = 1.0


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # First confirm admin-ajax is reachable
    step("checking admin-ajax.php reachability...")
    base = await client.get("/wp-admin/admin-ajax.php")
    if base is None:
        findings.append(
            Finding(
                severity="info",
                title="admin-ajax.php not reachable — skip throttle probe",
                evidence="No response from /wp-admin/admin-ajax.php.",
                remediation="No action needed.",
                url=client.url("/wp-admin/admin-ajax.php"),
            )
        )
        return findings

    statuses: list[int] = []
    for i in range(ATTEMPTS):
        if i > 0:
            await asyncio.sleep(PACING_SECONDS)
        step(f"admin-ajax throttle probe {i+1}/{ATTEMPTS}...")
        r = await client.get("/wp-admin/admin-ajax.php", params={"action": "wp-link-ajax"})
        if r is None:
            statuses.append(0)
            continue
        statuses.append(r.status_code)

    # If all 5 returned the same response, no rate-limit is applied to this endpoint
    if len(set(statuses)) == 1 and statuses[0] in (200, 400, 401, 403):
        findings.append(
            Finding(
                severity="low",
                title=f"admin-ajax.php applies no per-request throttle ({ATTEMPTS} identical responses)",
                evidence=(
                    f"5 calls to /wp-admin/admin-ajax.php?action=wp-link-ajax returned HTTP {statuses[0]} every time.\n"
                    "Many WP brute-force amplification attacks target admin-ajax actions rather than wp-login. "
                    "If your login rate-limiter only covers wp-login.php, admin-ajax may be a back door."
                ),
                remediation=(
                    "If you use a security plugin (Wordfence, Limit Login Attempts), verify its rate-limit covers "
                    "/wp-admin/admin-ajax.php as well as /wp-login.php. Many configure only the latter."
                ),
                url=client.url("/wp-admin/admin-ajax.php"),
            )
        )
    elif any(s in (429, 503) for s in statuses):
        findings.append(
            Finding(
                severity="info",
                title="admin-ajax.php applies throttling (good)",
                evidence=f"5 calls returned varied statuses: {statuses}, one or more was 429/503.",
                remediation="No action needed.",
                url=client.url("/wp-admin/admin-ajax.php"),
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title="admin-ajax.php throttle test inconclusive",
                evidence=f"Statuses across {ATTEMPTS} probes: {statuses}",
                remediation="No action needed.",
                url=client.url("/wp-admin/admin-ajax.php"),
            )
        )
    return findings
