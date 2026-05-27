"""A9 (v2.6.0) — WooCommerce Blocks Cart/Checkout REST drift.

WC 8.x introduced block-based Cart + Checkout, which exposes its own
REST namespace `/wc/store/v1/` (cart, checkout, products) alongside the
classic `/wc/v3/`. The two namespaces have DIFFERENT authentication
defaults — `/wc/store/v1/cart` accepts cookie+nonce (frontend-friendly)
while `/wc/v3/orders` requires Basic Auth with a consumer key. This
mismatch leads to surprises:

  • A REST policy that blocks /wc/v3/ at the WAF leaves /wc/store/v1/
    open.
  • A custom plugin that hooks `woocommerce_rest_check_permissions`
    only sees one namespace.

This check probes the read-only Store API endpoints to confirm they're
reachable, then surfaces a low-severity advisory listing every Store
API route the WAF should be hardened against.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_STORE_ROUTES = (
    "/wp-json/wc/store/v1/cart",
    "/wp-json/wc/store/v1/cart/items",
    "/wp-json/wc/store/v1/products",
    "/wp-json/wc/store/v1/checkout",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    open_routes: list[tuple[str, int]] = []
    for route in _STORE_ROUTES:
        step(f"WC Store-API probe: {route}")
        r = await client.get(route)
        if r is None:
            continue
        if r.status_code == 200:
            open_routes.append((route, r.status_code))

    if not open_routes:
        return findings

    findings.append(Finding(
        severity="low",
        title=f"WooCommerce Store API (/wc/store/v1) reachable — verify WAF + plugin filters cover this namespace",
        evidence=(
            "Reachable Store API routes (HTTP 200):\n  "
            + "\n  ".join(f"{r[0]}" for r in open_routes) + "\n\n"
            "The Store API namespace authenticates differently than /wc/v3 — "
            "cookie+nonce instead of Basic Auth. WAF rules and custom "
            "permission filters often miss it."
        ),
        remediation=(
            "1. Verify your WAF blocks /wp-json/wc/store/v1/ to the same standards "
            "as /wc/v3/.\n"
            "2. If you have a `woocommerce_rest_check_permissions` filter, "
            "ensure it also handles `woocommerce_store_api_*` filters.\n"
            "3. Audit `/wp-json/wc/store/v1/products` for accidentally-private "
            "products that shouldn't be browsable anonymously."
        ),
        url=client.url("/wp-json/wc/store/v1/"),
        extra={"reachable_routes": [r[0] for r in open_routes]},
    ))
    return findings
