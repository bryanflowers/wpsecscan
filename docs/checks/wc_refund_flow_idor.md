---
id: wc_refund_flow_idor
title: "WC refund-flow IDOR probe (F23)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 62
---

# WC refund-flow IDOR probe (F23)

**check_id**: `wc_refund_flow_idor`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-NTA

## What it does

F23 (v2.8.1) — WooCommerce refund-flow IDOR probe.

The WC refund endpoint `/wp-json/wc/v3/orders/<id>/refunds` is
gated on `manage_woocommerce` capability, but several payment-
gateway extensions (Stripe-Lite &lt; 9.3, Square &lt; 4.1) added
their own refund endpoints with broken authorisation. We
fingerprint payment plugins with known refund-IDOR CVEs.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F23: ⟨count⟩ payment gateway(s) with refund-IDOR history detected | Confirm each plugin is on the patched version listed. Audit custom refund endpoints for the canonical `current_user_can('manage_woocommerce') && $order->get_customer_id() === get_current_user_id()` (or admin-only) check before processing refunds. |
| info | F23: no payment-gateway plugins with refund-IDOR history detected | No action needed. |

## Evidence the check records

- F23: no payment-gateway plugins with refund-IDOR history detected: None of the 3 fingerprinted gateway plugin paths responded.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.2
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.8
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only wc_refund_flow_idor https://example.com
```

`only` runs this check alone and prints its findings.
