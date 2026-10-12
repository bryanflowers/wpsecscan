---
id: woo_blocks_checkout_drift
title: "WooCommerce Store API namespace drift (A9)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 152
---

# WooCommerce Store API namespace drift (A9)

**check_id**: `woo_blocks_checkout_drift`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-1188
**D3FEND**: D3-NTA

## What it does

A9 (v2.6.0) — WooCommerce Blocks Cart/Checkout REST drift.

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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | WooCommerce Store API (/wc/store/v1) reachable — verify WAF + plugin filters cover this namespace | 1. Verify your WAF blocks /wp-json/wc/store/v1/ to the same standards as /wc/v3/. 2. If you have a `woocommerce_rest_check_permissions` filter, ensure it also handles `woocommerce_store_api_*` filters. 3. Audit `/wp-json/wc/store/v1/products` for accidentally-private products that shouldn't be browsable anonymously. |

## Evidence the check records

- WooCommerce Store API (/wc/store/v1) reachable — verify WAF + plugin filters cover this namespace: Reachable Store API routes (HTTP 200): ⟨value⟩ The Store API namespace authenticates differently than /wc/v3 — cookie+nonce instead of Basic Auth. WAF rules and custom permission filters often miss it.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.8.22

## Run only this check

```
wpsecscan only woo_blocks_checkout_drift https://example.com
```

`only` runs this check alone and prints its findings.
