---
id: woocommerce_deep
title: "WC consumer-key/IDOR deep audit (#8+#9)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 96
---

# WC consumer-key/IDOR deep audit (#8+#9)

**check_id**: `woocommerce_deep`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-RAC

## What it does

#8 + #9 WooCommerce REST consumer-key leak + checkout-flow IDOR.

#8: scan HTML/JS for the `ck_*` / `cs_*` consumer key prefix patterns.
   These are WC REST API credentials sometimes bundled into front-end JS.

#9: probe order-status endpoints for sequential-ID IDOR — fetch /wc/store/v1
   order endpoint with adjacent IDs; if any returns 200 with order data,
   IDOR is present.

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WC orders/⟨oid⟩ accessible unauth — IDOR | Restrict /wp-json/wc/v3/* to authenticated admin (default behaviour). Audit any custom REST endpoint that returns orders without `current_user_can('view_woocommerce_reports')`. |
| critical | WooCommerce REST consumer-key/secret leaked in page HTML (⟨count⟩) | Rotate the leaked key/secret in WC &gt; Settings &gt; Advanced &gt; REST API. Find what wp_localize_script() call embedded it and remove. Never expose `cs_*` to the front-end — that's a secret. |
| info | WooCommerce deep audit — no key leaks or IDORs found | No action. |

## Evidence the check records

- WooCommerce deep audit — no key leaks or IDORs found: ck_/cs_ scan + order-endpoint probes returned clean.
- WC orders/⟨oid⟩ accessible unauth — IDOR: GET /wp-json/wc/v3/orders/⟨oid⟩ returned 200 with billing data — orders should require admin auth.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only woocommerce_deep https://example.com
```

`only` runs this check alone and prints its findings.
