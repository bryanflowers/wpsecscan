# WooCommerce REST + legacy-API audit

**check_id**: `woocommerce_audit`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WooCommerce-specific audit.

WooCommerce sites are the highest-value WP targets — PII + payment data.
Probes:
  - /wp-json/wc/v3/ namespace reachability (information disclosure)
  - /wp-json/wc/v3/orders, /customers, /products with OPTIONS to see which
    methods are exposed unauthenticated
  - ?wc-api=<endpoint> remnants (legacy v1 API; should be disabled)
  - Common WC plugin paths that often leak (Subscriptions, Bookings, etc.)

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only woocommerce_audit
```
