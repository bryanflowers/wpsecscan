"""F4 (v2.8.1) — WooCommerce pay-for-order link audit.

`?pay_for_order=true&key=wc_order_xxxx` links sometimes survive past
the order being paid AND may leak via Referer / browser-history if
served on HTTP. Defensive check: confirm /checkout/order-pay/ doesn't
emit a Referer-Policy header weaker than `strict-origin-when-cross-origin`.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F4: probing WC pay-for-order Referrer-Policy")
    r = await client.get("/checkout/order-pay/")
    if r is None:
        return []
    # v2.8.2 M10 — 404 means WooCommerce isn't installed (or the
    # checkout slug differs). Treat as not-WC and return nothing rather
    # than flagging Referrer-Policy on a non-WC site.
    if r.status_code == 404:
        return []
    if r.status_code not in (200, 301, 302):
        return []
    rp = (r.headers.get("referrer-policy") or "").lower().strip()
    if not rp:
        return [Finding(severity="medium",
                         title="F4: WC pay-for-order missing Referrer-Policy header",
                         evidence=f"GET /checkout/order-pay/ → HTTP {r.status_code}; no Referrer-Policy set.",
                         remediation=(
                             "Add `Referrer-Policy: strict-origin-when-cross-origin` "
                             "to your nginx/Apache/Cloudflare config so payment-link "
                             "URLs don't leak via Referer when the customer clicks "
                             "out from the receipt page."),
                         url=ctx["target"])]
    weak = ("no-referrer-when-downgrade", "unsafe-url", "origin")
    if any(w in rp for w in weak):
        return [Finding(severity="low",
                         title=f"F4: weak Referrer-Policy on pay-for-order: {rp}",
                         evidence=f"Referrer-Policy: {rp}",
                         remediation="Tighten to `strict-origin-when-cross-origin` or `no-referrer`.",
                         url=ctx["target"])]
    return [Finding(severity="info",
                     title=f"F4: WC pay-for-order Referrer-Policy is reasonable ({rp})",
                     evidence=f"Referrer-Policy: {rp}",
                     remediation="No action needed.",
                     url=ctx["target"])]
