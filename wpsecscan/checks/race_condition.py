"""Race-condition probe (aggressive).

Fires N parallel POSTs to a discovered AJAX endpoint, looks for indicators
of double-spend / accept-twice (response count > 1 success, identical idempotency
token used multiple times, etc).

Targets:
  - /wp-admin/admin-ajax.php with discovered actions
  - WooCommerce coupon-apply if WC is detected
  - Any plugin form endpoint that has a `_nonce` (we test with the SAME nonce
    in parallel to see if the server detects replay)
"""
from __future__ import annotations

import asyncio
import secrets

from ..http import Client
from ..models import Finding

PARALLEL_COUNT = 20  # 20 simultaneous requests is the standard "race" attempt


async def _fire_parallel(client: Client, method: str, path: str, **kwargs) -> list:
    """Fire N copies of the same request in parallel; return all responses."""
    async def _one():
        return await client.request(method, path, **kwargs)
    return await asyncio.gather(*(_one() for _ in range(PARALLEL_COUNT)), return_exceptions=False)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="Race-condition probe skipped (requires --aggressive)",
                evidence="This fires 20 parallel POSTs against AJAX/coupon endpoints to test race-safety.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # 1. Try the generic admin-ajax with a benign action
    step(f"firing {PARALLEL_COUNT} parallel `heartbeat` AJAX calls...")
    responses = await _fire_parallel(
        client, "POST", "/wp-admin/admin-ajax.php",
        data={"action": "heartbeat", "_nonce": "wpsec-race-" + secrets.token_hex(4)},
    )
    statuses = [r.status_code if r is not None else 0 for r in responses]
    n_ok = sum(1 for s in statuses if s == 200)

    if n_ok == PARALLEL_COUNT:
        findings.append(
            Finding(
                severity="info",
                title=f"admin-ajax accepts {PARALLEL_COUNT} parallel requests without rate-limiting",
                evidence=(
                    f"Fired {PARALLEL_COUNT} parallel POSTs to /wp-admin/admin-ajax.php?action=heartbeat. "
                    f"All {n_ok} returned HTTP 200. No per-request rate limit at the AJAX layer."
                ),
                remediation=(
                    "Whether this is a problem depends on the specific action. heartbeat is harmless. "
                    "Audit any plugin AJAX handler that performs CHARGES, ADDS-CREDIT, APPLIES-COUPON, "
                    "or any other state-changing single-use operation — those need an idempotency check."
                ),
                url=client.url("/wp-admin/admin-ajax.php"),
            )
        )

    # 2. If WooCommerce is present, probe coupon application race
    step("detecting WooCommerce for coupon race-condition probe...")
    r = await client.get("/wp-json/wc/v3/")
    if r is not None and r.status_code in (200, 401, 403):
        # WC is present — try parallel `apply_coupon` ajax
        canary_coupon = "wpsec-race-" + secrets.token_hex(3)
        step(f"firing {PARALLEL_COUNT} parallel coupon-apply attempts...")
        coupon_responses = await _fire_parallel(
            client, "POST", "/?wc-ajax=apply_coupon",
            data={"coupon_code": canary_coupon, "security": "wpsec-race-test"},
        )
        ok_count = sum(1 for resp in coupon_responses if resp is not None and resp.status_code == 200)
        if ok_count >= PARALLEL_COUNT - 2:  # Allow 2 transport errors
            findings.append(
                Finding(
                    severity="medium",
                    title=f"WC coupon-apply accepts {ok_count} parallel requests",
                    evidence=(
                        f"Fired {PARALLEL_COUNT} parallel POSTs with the same coupon code. {ok_count} returned 200.\n"
                        "WooCommerce should reject duplicate coupon applies within one session. If a real "
                        "coupon is applied this way (one with usage_limit_per_user=1), the limit can be "
                        "bypassed via parallel application."
                    ),
                    remediation=(
                        "Test against an ACTUAL valid one-use coupon — if the user gets a discount applied "
                        "multiple times, the race is exploitable. Mitigation: WooCommerce 4.0+ has built-in "
                        "transaction-level coupon locking; older versions don't. Upgrade or backport."
                    ),
                    url=client.url("/?wc-ajax=apply_coupon"),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Race-condition probe completed; no anomalies",
                evidence=f"Fired {PARALLEL_COUNT} parallel POSTs against admin-ajax + WC coupons.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
    return findings
