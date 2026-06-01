"""F67 (v2.8.3) — WC 9.x Stores API cart-add rate-limit probe.

The `/wp-json/wc/store/v1/cart/add-item` endpoint in WC 9.x has no
default rate-limit. Mass-add-to-cart is a documented DoS vector
(every add creates a session row in wp_options + a DB write). We
send a 5-request burst with the same trivial payload and measure
inter-request delay; if all 5 land in <1s, the endpoint is
unprotected.

Defensive — we use product_id=1 which usually 404s; we're measuring
THROTTLE, not actually adding items.
"""
from __future__ import annotations

import time

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F67: probing WC Stores API cart-add rate-limit")
    # Quick WC fingerprint — skip if no Store API.
    root = await client.get("/wp-json/wc/store/v1/")
    if root is None or root.status_code not in (200, 401, 403):
        return [Finding(severity="info",
                         title="F67: WC Store API not detected — rate-limit probe skipped",
                         evidence="No response from /wp-json/wc/store/v1/",
                         remediation="No action needed.",
                         url=ctx["target"])]
    # 5 rapid POSTs with the same payload. Track elapsed times.
    start = time.perf_counter()
    statuses: list[int] = []
    for _ in range(5):
        try:
            r = await client.post(
                "/wp-json/wc/store/v1/cart/add-item",
                json={"id": 1, "quantity": 1},
            )
            if r is not None:
                statuses.append(r.status_code)
        except Exception:  # noqa: BLE001
            continue
    elapsed = time.perf_counter() - start
    if len(statuses) < 3:
        return []  # WC not really enabled or endpoint blocked
    # If all 5 land in <1s AND none returned 429, no rate-limit is active.
    if elapsed < 1.0 and 429 not in statuses:
        return [Finding(severity="medium",
                         title="F67: WC Stores API cart-add has no rate-limit",
                         evidence=(
                             f"5 POST /wp-json/wc/store/v1/cart/add-item requests "
                             f"completed in {elapsed*1000:.0f}ms with no 429 response. "
                             f"Status codes: {statuses}. "
                             "Mass-add-to-cart can DoS the wp_options table on busy stores."),
                         remediation=(
                             "Add a rate-limit rule at your WAF / Cloudflare / "
                             "Wordfence (`/wp-json/wc/store/v1/cart/*` — limit to ~10 req/min "
                             "per IP). Consider WC 9.3+ which ships built-in throttling for "
                             "this endpoint."),
                         url=ctx["target"])]
    return [Finding(severity="info",
                     title="F67: WC Stores API cart-add appears rate-limited",
                     evidence=f"5 probes in {elapsed*1000:.0f}ms with statuses {statuses}.",
                     remediation="No action needed.",
                     url=ctx["target"])]
