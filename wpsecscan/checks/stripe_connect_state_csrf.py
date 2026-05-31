"""F5 (v2.8.1) — Stripe Connect / WooCommerce-Payments OAuth `state` audit.

The Stripe Connect OAuth flow requires a CSRF-protecting `state`
parameter on the connect URL. WC-Payments and several other Stripe
integrations historically forgot it or generated a predictable
value (timestamp, MD5(siteurl), etc.). A connect-back without state
verification lets an attacker bind their Stripe account to a
victim's WP install.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    # Check the admin page that surfaces the connect button. We can't
    # auth, so we passive-probe for the Stripe plugin's REST namespace.
    step("F5: probing for Stripe Connect plugins")
    found_plugin = None
    for marker in ("woocommerce-gateway-stripe", "woocommerce-payments",
                    "stripe-payments"):
        r = await client.head(f"/wp-content/plugins/{marker}/")
        if r is not None and r.status_code in (200, 301, 302, 403):
            found_plugin = marker
            break
    if not found_plugin:
        return [Finding(severity="info",
                         title="F5: No Stripe Connect plugin detected",
                         evidence="No woocommerce-gateway-stripe / woocommerce-payments / stripe-payments plugin path responded.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    return [Finding(severity="low",
                     title=f"F5: Stripe Connect plugin detected ({found_plugin}); audit `state` param manually",
                     evidence=(
                         f"Plugin path responded: /wp-content/plugins/{found_plugin}/\n"
                         "Cannot test the OAuth `state` parameter without "
                         "authenticated access; flag for manual review."),
                     remediation=(
                         "Verify plugin version is >= the patched CVE-2025 release "
                         "(WC-Stripe-Gateway >= 9.4.0, WC-Payments >= 8.7.0). "
                         "Audit the connect-button HTML for a `state=` param of "
                         "≥32 random bytes."),
                     url=ctx["target"])]
