---
id: wc_draft_order_escalation
title: "WC draft-order state-machine probe (F3)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 74
---

# WC draft-order state-machine probe (F3)

**check_id**: `wc_draft_order_escalation`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-NTA

## What it does

F3 (v2.8.1) — WooCommerce draft-order state-machine probe.

Tests whether the WC Store Checkout API enforces order-state
transitions correctly. A pending → completed transition without a
payment-intent verification is a CISA-KEV-class vuln in some WC
extensions (Stripe Lite 2024, Square 2025).

Defensive — we only check the endpoint shape; no actual transition
attempted (would require an auth cookie + a real cart anyway).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/info | ⟨title⟩ | Update WC core + payment plugins to current. |
| info | F3: WC Store API checkout endpoint unreachable | No action needed if WC isn't installed. |

## Evidence the check records

- F3: WC Store API checkout endpoint unreachable: No response from /wp-json/wc/store/v1/checkout

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
wpsecscan only wc_draft_order_escalation https://example.com
```

`only` runs this check alone and prints its findings.
