---
id: wc_cart_abandonment_xss
title: "WC cart-abandonment plugin XSS probe (F2)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 66
---

# WC cart-abandonment plugin XSS probe (F2)

**check_id**: `wc_cart_abandonment_xss`
**aggressive**: no
**category**: Injection & client-side
**max severity**: medium
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript
**CWE**: CWE-79
**D3FEND**: D3-NTA

## What it does

F2 (v2.8.1) — WC cart-abandonment plugin stored-XSS probe.

Retainful, CartFlows Cart Abandonment Recovery, and WooCommerce Cart
Abandonment Recovery all collect guest emails on the checkout page
and render them server-side in admin email templates. Pre-2024 CVE
disclosures showed several mis-rendered the email field unescaped.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F2: cart-abandonment plugin(s) present (⟨count⟩); audit email-template escaping | These plugins render guest emails in admin email templates; verify the plugin is updated to a post-CVE-2024 version (Retainful &gt;= 1.16.1, CartFlows-CA &gt;= 1.10.0, WC-CAR &gt;= 1.3.0). Consider a WAF rule that strips HTML from the email field on submission as defence in depth. |
| info | F2: WC cart-abandonment plugin not detected | No action needed. |

## Evidence the check records

- F2: cart-abandonment plugin(s) present (⟨count⟩); audit email-template escaping: Detected: ⟨value⟩
- F2: WC cart-abandonment plugin not detected: None of Retainful/CartFlows-CA/WC-CAR present.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan only wc_cart_abandonment_xss https://example.com
```

`only` runs this check alone and prints its findings.
