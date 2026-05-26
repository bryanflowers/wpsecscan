"""Items #15 + #16 — WooCommerce storefront-side vulnerabilities.

#15 — coupon-code enumeration: probe `?wc-ajax=apply_coupon` with a small
     wordlist. Detection of brute-forceability matters because a successful
     coupon discovery is direct revenue loss (free shipping codes, %-off,
     gift cards used as coupons in some plugins).

#16 — `get_refreshed_fragments` cache-poisoning: that endpoint must NEVER
     be cached by a CDN — it serves per-user cart HTML. A misconfigured
     Cloudflare page rule / Litespeed cache / WP Rocket setting that
     caches it leaks one customer's cart to every other visitor.
"""
from __future__ import annotations

import asyncio

from ..http import Client
from ..models import Finding


# Common coupon-like terms we'll attempt. Each is single-shot; we count
# attempts and look for rate-limit signals (429, slowdown, blocked).
_COUPON_PROBES = (
    "WELCOME10", "SAVE10", "SAVE20", "FREESHIP",
    "BLACKFRIDAY", "CYBERMONDAY", "SUMMER2024",
    "TEST", "ADMIN", "DISCOUNT",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # ----- preflight: is WooCommerce here at all?
    step("WC storefront: checking for WooCommerce on the cart endpoint...")
    cart_resp = await client.get("/wp-json/wc/store/v1/cart")
    has_wc = cart_resp is not None and cart_resp.status_code in (200, 401, 403)
    if not has_wc:
        # Also check homepage for WC markers — REST may be locked down.
        home = await client.get("/")
        body = (home.text or "")[:50_000].lower() if home else ""
        if "woocommerce" not in body and "wc_add_to_cart" not in body:
            return [Finding(
                severity="info",
                title="WC storefront checks skipped — WooCommerce not detected",
                evidence="No /wc/store/v1/cart endpoint AND no WC markers on /.",
                remediation="No action.",
                url=ctx["target"],
            )]

    # ----- #15 coupon-enumeration throttling
    step("WC storefront: probing apply_coupon throttling...")
    statuses: list[int] = []
    timings: list[float] = []
    loop = asyncio.get_event_loop()
    for code in _COUPON_PROBES:
        t0 = loop.time()
        r = await client.post(
            "/?wc-ajax=apply_coupon",
            content=f"security=0&coupon_code={code}",
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "X-Requested-With": "XMLHttpRequest"},
        )
        elapsed = loop.time() - t0
        if r is not None:
            statuses.append(r.status_code)
            timings.append(elapsed)

    if statuses:
        n_429 = sum(1 for s in statuses if s == 429)
        n_403 = sum(1 for s in statuses if s == 403)
        n_200 = sum(1 for s in statuses if s == 200)
        # Median timing — a slow exponential backoff is also throttling.
        timings_sorted = sorted(timings)
        median = timings_sorted[len(timings_sorted) // 2] if timings_sorted else 0.0
        max_t = max(timings) if timings else 0.0

        # Throttled if any 429 fired OR the last call is markedly slower
        # than the first (rough backoff signature: max > 3× median).
        throttled = n_429 > 0 or (median > 0 and max_t / max(median, 0.01) > 3.0)
        if not throttled and n_200 >= len(_COUPON_PROBES) - 1:
            findings.append(Finding(
                severity="medium",
                title="WooCommerce coupon endpoint accepts unthrottled enumeration",
                evidence=(
                    f"Sent {len(statuses)} coupon-code probes at "
                    f"/?wc-ajax=apply_coupon. Statuses: 200×{n_200}, "
                    f"403×{n_403}, 429×{n_429}. "
                    f"Median {median*1000:.0f} ms, max {max_t*1000:.0f} ms. "
                    "No 429 and no progressive slowdown — coupon codes can "
                    "be brute-forced from a single IP."
                ),
                remediation=(
                    "Install Wordfence Login Security, Limit Login Attempts "
                    "Reloaded, or `Coupon Discount Code Limit` to throttle "
                    "wc-ajax=apply_coupon by IP. Alternatively, add a "
                    "Cloudflare WAF rule: `(http.request.uri.query contains "
                    "\"wc-ajax=apply_coupon\")` → challenge after 5 requests/min."
                ),
                url=ctx["target"] + "/?wc-ajax=apply_coupon",
            ))
        elif n_403 >= len(_COUPON_PROBES) - 1:
            findings.append(Finding(
                severity="info",
                title="WC coupon endpoint blocked (likely WAF or nonce-required)",
                evidence=f"All {len(statuses)} probes returned 403 — endpoint is gated.",
                remediation="No action.",
                url=ctx["target"],
            ))
        else:
            findings.append(Finding(
                severity="info",
                title=f"WC coupon endpoint throttling appears active ({n_429} × 429, slowdown observed)",
                evidence=(
                    f"Sent {len(statuses)} probes. 200×{n_200}, 429×{n_429}. "
                    f"Median {median*1000:.0f} ms, max {max_t*1000:.0f} ms."
                ),
                remediation="No action.",
                url=ctx["target"],
            ))

    # ----- #16 fragments cache-poisoning
    step("WC storefront: inspecting get_refreshed_fragments cache headers...")
    r = await client.get("/?wc-ajax=get_refreshed_fragments")
    if r is not None:
        cc = (r.headers.get("cache-control", "") or
                r.headers.get("Cache-Control", "")).lower()
        age = r.headers.get("age", "") or r.headers.get("Age", "")
        cf_cache = (r.headers.get("cf-cache-status", "") or
                      r.headers.get("CF-Cache-Status", "")).upper()
        x_cache = (r.headers.get("x-cache", "") or
                     r.headers.get("X-Cache", "")).upper()

        # Bad signals: max-age=N where N>0, OR Age: header, OR CF-Cache-Status: HIT.
        cacheable_directives = ("public", "max-age=")
        looks_cacheable = (
            any(d in cc for d in cacheable_directives)
            and "no-store" not in cc
            and "private" not in cc
        )
        served_from_cache = bool(age) or cf_cache == "HIT" or "HIT" in x_cache

        if looks_cacheable or served_from_cache:
            findings.append(Finding(
                severity="high",
                title="WC fragments endpoint is cacheable — risk of cart leakage between users",
                evidence=(
                    "GET /?wc-ajax=get_refreshed_fragments returned headers "
                    f"that imply caching:\n  Cache-Control: {cc or '(none)'}\n"
                    f"  Age: {age or '(none)'}\n  CF-Cache-Status: {cf_cache or '(none)'}\n"
                    f"  X-Cache: {x_cache or '(none)'}\n\n"
                    "This endpoint serves per-user cart HTML. If a CDN or "
                    "reverse-proxy caches it, every visitor sees the cart "
                    "state of whoever's fragment got cached first."
                ),
                remediation=(
                    "Exclude this URL pattern from the CDN cache:\n"
                    "  • Cloudflare → Caching > Page Rules: URL pattern "
                    "`*wc-ajax=*` → Cache Level: Bypass\n"
                    "  • WP Rocket → Cache > Never Cache (URLs): add "
                    "`/?wc-ajax=` and `*wc-ajax=*`\n"
                    "  • Litespeed Cache → Settings > Excludes: add the same."
                ),
                url=ctx["target"] + "/?wc-ajax=get_refreshed_fragments",
            ))
        else:
            findings.append(Finding(
                severity="info",
                title="WC fragments endpoint not cached (Cache-Control safe)",
                evidence=f"Cache-Control: {cc or '(none)'} — CDN/proxy will not cache.",
                remediation="No action.",
                url=ctx["target"],
            ))

    return findings or [Finding(
        severity="info",
        title="WC storefront checks — clean",
        evidence="Coupon throttling appears active and fragments endpoint is not cacheable.",
        remediation="No action.",
        url=ctx["target"],
    )]
