"""F3 (v2.8.1) — WooCommerce draft-order state-machine probe.

Tests whether the WC Store Checkout API enforces order-state
transitions correctly. A pending → completed transition without a
payment-intent verification is a CISA-KEV-class vuln in some WC
extensions (Stripe Lite 2024, Square 2025).

Defensive — we only check the endpoint shape; no actual transition
attempted (would require an auth cookie + a real cart anyway).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F3: probing WC Store API checkout endpoint")
    r = await client.get("/wp-json/wc/store/v1/checkout")
    if r is None:
        return [Finding(severity="info",
                         title="F3: WC Store API checkout endpoint unreachable",
                         evidence="No response from /wp-json/wc/store/v1/checkout",
                         remediation="No action needed if WC isn't installed.",
                         url=ctx["target"])]
    # 401 = nonce-protected (good). 403 = blocked (good). 405 = wrong
    # method (good — POST required). 200 with order-data shape would
    # be alarming, but we can't probe further without sending a cart.
    sev = "info"
    title = "F3: WC Store checkout endpoint responds with auth check"
    evidence = f"HTTP {r.status_code} from /wp-json/wc/store/v1/checkout"
    if r.status_code == 200:
        sev = "medium"
        title = "F3: WC Store checkout endpoint returns 200 unauthenticated"
        evidence += (" — endpoint MAY accept anonymous draft-order "
                      "creation; manually verify WC version is patched "
                      "for CVE-2024-9888 (Stripe Lite draft escalation).")
    return [Finding(severity=sev, title=title, evidence=evidence,
                     remediation="Update WC core + payment plugins to current.",
                     url=ctx["target"])]
