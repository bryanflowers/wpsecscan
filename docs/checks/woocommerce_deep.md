# WC consumer-key/IDOR deep audit (#8+#9)

**check_id**: `woocommerce_deep`
**aggressive**: no
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

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan --target https://example.com --only woocommerce_deep
```
