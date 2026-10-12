---
id: woocommerce_storefront
title: "WC coupon-enum throttle + fragments cache-poisoning"
severity_max: high
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 267
---

# WC coupon-enum throttle + fragments cache-poisoning

**check_id**: `woocommerce_storefront`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: high
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-307
**D3FEND**: D3-RAC

## What it does

Items #15 + #16 — WooCommerce storefront-side vulnerabilities.

#15 — coupon-code enumeration: probe `?wc-ajax=apply_coupon` with a small
     wordlist. Detection of brute-forceability matters because a successful
     coupon discovery is direct revenue loss (free shipping codes, %-off,
     gift cards used as coupons in some plugins).

#16 — `get_refreshed_fragments` cache-poisoning: that endpoint must NEVER
     be cached by a CDN — it serves per-user cart HTML. A misconfigured
     Cloudflare page rule / Litespeed cache / WP Rocket setting that
     caches it leaks one customer's cart to every other visitor.

## Request footprint

The module contains 4 request call(s) to the target (GET x3, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | WC fragments endpoint is cacheable — risk of cart leakage between users | Exclude this URL pattern from the CDN cache: • Cloudflare → Caching &gt; Page Rules: URL pattern `*wc-ajax=*` → Cache Level: Bypass • WP Rocket → Cache &gt; Never Cache (URLs): add `/?wc-ajax=` and `*wc-ajax=*` • Litespeed Cache → Settings &gt; Excludes: add the same. |
| medium | WooCommerce coupon endpoint accepts unthrottled enumeration | Install Wordfence Login Security, Limit Login Attempts Reloaded, or `Coupon Discount Code Limit` to throttle wc-ajax=apply_coupon by IP. Alternatively, add a Cloudflare WAF rule: `(http.request.uri.query contains "wc-ajax=apply_coupon")` → challenge after 5 requests/min. |
| info | WC coupon endpoint blocked (likely WAF or nonce-required) | No action. |
| info | WC coupon endpoint throttling appears active (⟨n_429⟩ × 429, slowdown observed) | No action. |
| info | WC fragments endpoint not cached (Cache-Control safe) | No action. |
| info | WC storefront checks skipped — WooCommerce not detected | No action. |
| info | WC storefront checks — clean | No action. |

## Evidence the check records

- WC storefront checks — clean: Coupon throttling appears active and fragments endpoint is not cacheable.
- WC storefront checks skipped — WooCommerce not detected: No /wc/store/v1/cart endpoint AND no WC markers on /.
- WooCommerce coupon endpoint accepts unthrottled enumeration: Sent ⟨count⟩ coupon-code probes at /?wc-ajax=apply_coupon. Statuses: 200×⟨n_200⟩, 403×⟨n_403⟩, 429×⟨n_429⟩. Median ⟨value⟩ ms, max ⟨value⟩ ms. No 429 and no progressive slowdown — coupon codes can be brute-forced from a single IP.
- WC fragments endpoint is cacheable — risk of cart leakage between users: GET /?wc-ajax=get_refreshed_fragments returned headers that imply caching: Cache-Control: ⟨value⟩ Age: ⟨value⟩ CF-Cache-Status: ⟨value⟩ X-Cache: ⟨value⟩ This endpoint serves per-user cart HTML. If a CDN or reverse-proxy caches it, every visitor sees the cart state of whoever's fragment got cached first.
- WC fragments endpoint not cached (Cache-Control safe): Cache-Control: ⟨value⟩ — CDN/proxy will not cache.
- WC coupon endpoint blocked (likely WAF or nonce-required): All ⟨count⟩ probes returned 403 — endpoint is gated.
- WC coupon endpoint throttling appears active (⟨n_429⟩ × 429, slowdown observed): Sent ⟨count⟩ probes. 200×⟨n_200⟩, 429×⟨n_429⟩. Median ⟨value⟩ ms, max ⟨value⟩ ms.

## Compliance mapping

- **compliance_map / pci_dss**: 6.5.10
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.8.5

## Run only this check

```
wpsecscan only woocommerce_storefront https://example.com
```

`only` runs this check alone and prints its findings.
