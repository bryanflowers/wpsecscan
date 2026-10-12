---
id: woocommerce_order_idor
title: "Unauthenticated WC order IDOR probe"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 102
---

# Unauthenticated WC order IDOR probe

**check_id**: `woocommerce_order_idor`
**aggressive**: no
**category**: Authentication & session
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1213 — Data from Information Repositories

## What it does

Unauthenticated WooCommerce order IDOR probe.

A site with WooCommerce REST API exposing /wc/v3/orders/{id} unauthenticated
leaks every customer's billing email + phone + address. This is a recurring
real-world configuration bug when WC REST auth is disabled for legacy
integration testing and left that way in production.

Probes /wc/v3/orders/1..3. Fires critical if any returns 200 with
billing-shaped fields. Light probe — exactly 3 requests.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WooCommerce orders leaked unauthenticated (⟨count⟩ confirmed) | 1. IMMEDIATELY: lock /wp-json/wc/v3/orders behind authentication. Either disable the WooCommerce REST API entirely or require a valid consumer-key + consumer-secret pair. 2. Audit access logs for sequential /orders/{N} probes to estimate scope of any prior data exposure. 3. GDPR / state-AG: this is likely a notifiable data breach. Consult counsel on disclosure obligations. |

## Evidence the check records

- WooCommerce orders leaked unauthenticated (⟨count⟩ confirmed): Unauthenticated GETs to /wp-json/wc/v3/orders/{1,2,3} returned PII: ⟨lines⟩ Every customer order on this site is enumerable by ID without any authentication. Billing email + phone + address + line items are all exposed.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only woocommerce_order_idor https://example.com
```

`only` runs this check alone and prints its findings.
