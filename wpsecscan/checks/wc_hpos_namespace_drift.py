"""F68 (v2.8.3) — WooCommerce HPOS namespace-drift advisory.

WC 9.0+ ships High-Performance Order Storage (HPOS), which moves
orders from posts/postmeta tables to dedicated wc_orders tables.
When HPOS is active, `/wp-json/wc/v3/orders` can return data from a
different DB table than the admin UI shows, and per-order permission
checks must be applied in BOTH code paths. Misconfigured custom
plugins frequently authorize one but not the other.

We detect HPOS via the `/wp-json/wc-admin/features` endpoint and emit
an advisory when active so the operator audits any custom order-
modifying plugin code for dual-path permission checks.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F68: probing WC HPOS feature flag")
    r = await client.get("/wp-json/wc-admin/features")
    if r is None or r.status_code != 200:
        return [Finding(severity="info",
                         title="F68: wc-admin features endpoint unreachable; HPOS state unknown",
                         evidence=f"GET /wp-json/wc-admin/features → {r.status_code if r else 'no response'}",
                         remediation="No action needed if WC isn't installed.",
                         url=ctx["target"])]
    try:
        data = r.json()
    except ValueError:
        return []
    # The endpoint returns a list of {slug, is_enabled} or a dict.
    hpos_enabled = False
    if isinstance(data, list):
        for feat in data:
            if isinstance(feat, dict) and "hpos" in (feat.get("slug", "") or "").lower():
                hpos_enabled = bool(feat.get("is_enabled"))
                break
    elif isinstance(data, dict):
        hpos_enabled = bool(data.get("hpos") or data.get("custom_order_tables"))
    if hpos_enabled:
        return [Finding(severity="low",
                         title="F68: WC HPOS active — audit custom order code for dual-path permission checks",
                         evidence=(
                             "WC reports HPOS (High-Performance Order Storage) is enabled. "
                             "Orders are stored in wc_orders tables (not posts/postmeta). "
                             "Any custom plugin that touches orders must apply permission "
                             "checks via both `wc_get_order()` AND the legacy "
                             "`get_post()` paths — a common bug class authorizes one but "
                             "not the other, exposing orders via the unaudited path."),
                         remediation=(
                             "Run WC's built-in `wp wc hpos verify_orders` (CLI) to confirm "
                             "the legacy and HPOS tables are consistent. Audit custom "
                             "plugins for direct `$wpdb->prefix . 'posts'` queries against "
                             "the `shop_order` post type — these silently bypass HPOS data."),
                         url=ctx["target"])]
    return [Finding(severity="info",
                     title="F68: WC HPOS not active",
                     evidence="HPOS flag not set in wc-admin features.",
                     remediation="No action needed.",
                     url=ctx["target"])]
