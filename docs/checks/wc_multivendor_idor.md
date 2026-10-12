---
id: wc_multivendor_idor
title: "WC multi-vendor (Dokan/WCFM) IDOR probe (F19)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 61
---

# WC multi-vendor (Dokan/WCFM) IDOR probe (F19)

**check_id**: `wc_multivendor_idor`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-NTA

## What it does

F19 (v2.8.1) — WooCommerce multi-vendor (Dokan/WCFM) IDOR probe.

Dokan + WCFM allow vendors to manage their products via REST.
Historical IDOR bugs let vendor A read/edit vendor B's products by
incrementing an ID. We fingerprint the plugin and emit a
moderate-severity advisory pointing to CVE histories.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F19: ⟨count⟩ multi-vendor plugin(s) detected — IDOR-history audit required | Confirm plugin versions are &gt;= the patched releases above. Audit any custom vendor-dashboard endpoints for `current_user_can('manage_woocommerce')` OR an explicit ownership check that compares `get_post_field('post_author')` to `get_current_user_id()`. |
| info | F19: no multi-vendor plugins detected | No action needed. |

## Evidence the check records

- F19: no multi-vendor plugins detected: None of the 4 fingerprinted multi-vendor plugin paths responded.

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
wpsecscan only wc_multivendor_idor https://example.com
```

`only` runs this check alone and prints its findings.
