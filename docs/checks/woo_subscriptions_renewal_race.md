---
id: woo_subscriptions_renewal_race
title: "WC Subscriptions duplicate-renewal race patch audit (A10)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 157
---

# WC Subscriptions duplicate-renewal race patch audit (A10)

**check_id**: `woo_subscriptions_renewal_race`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-362
**D3FEND**: D3-MA

## What it does

A10 (v2.6.0) — WooCommerce Subscriptions duplicate-renewal probe.

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

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WooCommerce Subscriptions detected — verify duplicate-renewal race patch is applied | 1. Confirm plugin version &gt;= 5.5 via wp-admin → Plugins. 2. Audit your payment gateway's idempotency-key configuration; Stripe + Adyen support an Idempotency-Key header that prevents double-charges at the gateway level. Confirm WC is sending it. 3. Subscribe to woocommerce.com security advisories for this plugin specifically — it has a high CVE rate. |

## Evidence the check records

- WooCommerce Subscriptions detected — verify duplicate-renewal race patch is applied: WC Subscriptions plugin fingerprinted on this install. Historical bug class: simultaneous renewal POSTs can charge the customer twice because the pre-renewal idempotency check is not atomic. Patched in 2.5.6 (released 2020) and again in 5.5 (2024) for a different code path.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-2
- **compliance_map / iso_27001**: A.8.25

## Run only this check

```
wpsecscan only woo_subscriptions_renewal_race https://example.com
```

`only` runs this check alone and prints its findings.
