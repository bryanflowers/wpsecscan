---
id: woocommerce_audit
title: "WooCommerce REST + legacy-API audit"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 173
---

# WooCommerce REST + legacy-API audit

**check_id**: `woocommerce_audit`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WooCommerce-specific audit.

WooCommerce sites are the highest-value WP targets — PII + payment data.
Probes:
  - /wp-json/wc/v3/ namespace reachability (information disclosure)
  - /wp-json/wc/v3/orders, /customers, /products with OPTIONS to see which
    methods are exposed unauthenticated
  - ?wc-api=&lt;endpoint&gt; remnants (legacy v1 API; should be disabled)
  - Common WC plugin paths that often leak (Subscriptions, Bookings, etc.)

## Request footprint

The module contains 6 request call(s) to the target (GET x5, REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high/medium | WC REST namespace ⟨path⟩ leaks data unauthenticated (HTTP ⟨code⟩, ~⟨count⟩ records) | Confirm 'REST API' under WooCommerce → Settings → Advanced has 'Permission' set; if so, the leak is a plugin overriding the auth check. Audit any plugin that calls `register_rest_route` against the `wc/v3` namespace. Or add at the edge: Nginx `location ~ ^/wp-json/wc { allow <office-ip>; deny all; }`. |
| critical/high/medium | WC REST ⟨path⟩ advertises write methods: ⟨methods⟩ | Test the actual write: `curl -X POST {path} -d 'test=1'`. If 401/403, you're OK. If 200/201, you have unauth writes. |
| medium | WooCommerce legacy ?wc-api= endpoints still reachable (⟨count⟩) | The legacy wc-api was deprecated in WC 3.0; modern installs should use /wp-json/wc/v3/. Disable via plugin or in functions.php: `remove_action('parse_request', 'wc_api_handler');` |
| info | WooCommerce detected — no obvious REST or legacy-API leaks | No action. |
| info | WooCommerce ecosystem plugins detected (⟨count⟩) | Cross-reference each plugin's version with the Wordfence CVE database (run `wpsecscan --update-db` for fresh data). WC Subscriptions and WC Payments have had multiple unauth-vulns in 2024. |
| info | WooCommerce not detected — WC-specific audit skipped | No action. |

## Evidence the check records

- WooCommerce not detected — WC-specific audit skipped: Neither /wp-json/wc/v3/ nor the homepage indicated WooCommerce is installed.
- WooCommerce legacy ?wc-api= endpoints still reachable (⟨count⟩): Reachable: ⟨value⟩
- WooCommerce ecosystem plugins detected (⟨count⟩): Found: ⟨value⟩
- WooCommerce detected — no obvious REST or legacy-API leaks: REST namespaces require auth, no legacy wc-api endpoints reachable.
- WC REST namespace ⟨path⟩ leaks data unauthenticated (HTTP ⟨code⟩, ~⟨count⟩ records): GET ⟨path⟩ returned ⟨code⟩ with content. The WooCommerce REST API should require authentication for orders/customers/system_status. Unauthenticated reads expose PII + business intel.
- WC REST ⟨path⟩ advertises write methods: ⟨methods⟩: OPTIONS ⟨path⟩ -&gt; Allow: ⟨methods⟩. OPTIONS reflects every registered method even if auth is enforced — verify each method actually rejects anonymous writes.

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only woocommerce_audit https://example.com
```

`only` runs this check alone and prints its findings.
