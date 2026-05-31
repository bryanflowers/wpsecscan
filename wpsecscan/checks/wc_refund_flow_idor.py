"""F23 (v2.8.1) — WooCommerce refund-flow IDOR probe.

The WC refund endpoint `/wp-json/wc/v3/orders/<id>/refunds` is
gated on `manage_woocommerce` capability, but several payment-
gateway extensions (Stripe-Lite < 9.3, Square < 4.1) added
their own refund endpoints with broken authorisation. We
fingerprint payment plugins with known refund-IDOR CVEs.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F23: probing payment-gateway refund endpoints")
    detected = []
    for path, label, version_note in (
        ("/wp-content/plugins/woocommerce-stripe-lite/",
         "Stripe-Lite", "patched in 9.3.0"),
        ("/wp-content/plugins/woocommerce-square/",
         "Square", "patched in 4.1.0"),
        ("/wp-content/plugins/woocommerce-paypal-payments/",
         "PayPal", "patched in 2.9.4"),
    ):
        r = await client.head(path)
        if r is not None and r.status_code in (200, 301, 302, 403):
            detected.append((label, version_note))
    if not detected:
        return [Finding(severity="info",
                         title="F23: no payment-gateway plugins with refund-IDOR history detected",
                         evidence="None of the 3 fingerprinted gateway plugin paths responded.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    lines = [f"{lbl}: {note}" for lbl, note in detected]
    return [Finding(severity="medium",
                     title=f"F23: {len(detected)} payment gateway(s) with refund-IDOR history detected",
                     evidence="\n".join(lines),
                     remediation=(
                         "Confirm each plugin is on the patched version listed. "
                         "Audit custom refund endpoints for the canonical "
                         "`current_user_can('manage_woocommerce') && "
                         "$order->get_customer_id() === get_current_user_id()` "
                         "(or admin-only) check before processing refunds."),
                     url=ctx["target"])]
