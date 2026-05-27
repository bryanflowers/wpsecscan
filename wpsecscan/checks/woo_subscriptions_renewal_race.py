"""A10 (v2.6.0) — WooCommerce Subscriptions duplicate-renewal probe.

WC Subscriptions exposes `/wp-json/wc/v3/subscriptions/{id}` and the
legacy `/wc-api/wc_stripe` / `/wc-api/woocommerce_subscriptions`
endpoints. The renewal flow has historically been vulnerable to a
duplicate-charge race when two near-simultaneous POSTs arrive — the
plugin's pre-renewal idempotency check uses a DB lookup that isn't
atomic.

This check is PASSIVE: it fingerprints the plugin from the homepage
HTML + the existence of `/wc-api/wc_subscriptions_renewal_payment`
and emits an advisory recommending the operator verify the version
is patched (2.5.6+). We do NOT issue duplicate renewal requests in
the passive scan.

Aggressive mode could attempt the actual race but that risks real
customer charges — out of scope.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_FINGERPRINT_PATHS = (
    "/wp-content/plugins/woocommerce-subscriptions/",
    "/wc-api/wc_subscriptions_renewal_payment",
    "/wp-json/wc/v3/subscriptions",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    home = await client.get("/")
    body = (home.text or "") if home else ""
    fingerprinted = "woocommerce-subscriptions" in body.lower()

    for path in _FINGERPRINT_PATHS:
        step(f"WC Subscriptions probe: {path}")
        r = await client.get(path)
        if r is not None and r.status_code in (200, 401, 403, 405):
            fingerprinted = True
            break

    if not fingerprinted:
        return findings

    findings.append(Finding(
        severity="medium",
        title="WooCommerce Subscriptions detected — verify duplicate-renewal race patch is applied",
        evidence=(
            "WC Subscriptions plugin fingerprinted on this install.\n"
            "Historical bug class: simultaneous renewal POSTs can charge the\n"
            "customer twice because the pre-renewal idempotency check is\n"
            "not atomic. Patched in 2.5.6 (released 2020) and again in 5.5\n"
            "(2024) for a different code path."
        ),
        remediation=(
            "1. Confirm plugin version >= 5.5 via wp-admin → Plugins.\n"
            "2. Audit your payment gateway's idempotency-key configuration; "
            "Stripe + Adyen support an Idempotency-Key header that prevents "
            "double-charges at the gateway level. Confirm WC is sending it.\n"
            "3. Subscribe to woocommerce.com security advisories for this plugin "
            "specifically — it has a high CVE rate."
        ),
        url=client.url("/"),
        extra={"category": "payments-race"},
    ))
    return findings
