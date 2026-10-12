---
id: stripe_connect_state_csrf
title: "Stripe-Connect OAuth state-CSRF audit (F5)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 102
---

# Stripe-Connect OAuth state-CSRF audit (F5)

**check_id**: `stripe_connect_state_csrf`
**aggressive**: no
**category**: Authentication & session
**max severity**: low
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-352
**D3FEND**: D3-IAA

## What it does

F5 (v2.8.1) — Stripe Connect / WooCommerce-Payments OAuth `state` audit.

The Stripe Connect OAuth flow requires a CSRF-protecting `state`
parameter on the connect URL. WC-Payments and several other Stripe
integrations historically forgot it or generated a predictable
value (timestamp, MD5(siteurl), etc.). A connect-back without state
verification lets an attacker bind their Stripe account to a
victim's WP install.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | F5: Stripe Connect plugin detected (⟨found_plugin⟩); audit `state` param manually | Verify plugin version is &gt;= the patched CVE-2025 release (WC-Stripe-Gateway &gt;= 9.4.0, WC-Payments &gt;= 8.7.0). Audit the connect-button HTML for a `state=` param of ≥32 random bytes. |
| info | F5: No Stripe Connect plugin detected | No action needed. |

## Evidence the check records

- F5: Stripe Connect plugin detected (⟨found_plugin⟩); audit `state` param manually: Plugin path responded: /wp-content/plugins/⟨found_plugin⟩/ Cannot test the OAuth `state` parameter without authenticated access; flag for manual review.
- F5: No Stripe Connect plugin detected: No woocommerce-gateway-stripe / woocommerce-payments / stripe-payments plugin path responded.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.8
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only stripe_connect_state_csrf https://example.com
```

`only` runs this check alone and prints its findings.
