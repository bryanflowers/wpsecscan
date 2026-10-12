---
id: cookie_banner_cosmetic_vs_blocking
title: "Cookie banner cosmetic-vs-blocking probe (F69)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 175
---

# Cookie banner cosmetic-vs-blocking probe (F69)

**check_id**: `cookie_banner_cosmetic_vs_blocking`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-359
**D3FEND**: D3-FA

## What it does

F69 (v2.8.3) — distinguish cosmetic vs blocking cookie banners.

The existing `cookie_consent` check detects whether a banner HTML
element is present but does not test whether the banner is BLOCKING
(scripts only load after interaction) or COSMETIC (scripts load
regardless, banner just exists to look compliant).

We make two requests:
  1. Vanilla GET → record which tracking cookies are set
  2. GET with `Cookie: cookielawinfo-checkbox-* = no` → re-check
     whether the tracking cookies are STILL set

If the same _ga / _fbp / _ttp cookies appear in both responses, the
banner is cosmetic and the site is non-compliant with EU ePrivacy +
GDPR consent-first principles.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F69: cookie banner is COSMETIC — trackers load before consent | Configure the banner plugin's BLOCKING mode (most plugins call it 'Block scripts before consent' or 'Strict mode'). For Complianz: Wizard step 4 → 'Use plugin script-blocker'. For CookieYes / CookieBot: enable 'Auto-blocking'. For custom implementations, gate the GA/Pixel `<script>` tags on a consent flag set by the banner's accept-button. |
| info | F69: cookie banner appears blocking (no trackers without consent) | No action needed. |
| info | F69: no cookie banner detected | No action needed (or add a banner if GDPR-applicable). |

## Evidence the check records

- F69: cookie banner appears blocking (no trackers without consent): Vanilla request set ⟨value⟩ trackers; reject-cookies request set ⟨value⟩.
- F69: no cookie banner detected: None of the 7 common banner markers in homepage HTML.
- F69: cookie banner is COSMETIC — trackers load before consent: Same tracking cookie(s) set on BOTH the vanilla request AND a reject-cookies request: ⟨value⟩. GDPR/ePrivacy require non-essential trackers to load only AFTER explicit consent.

## Compliance mapping

- **compliance_map / pci_dss**: 12.10
- **compliance_map / nist_800_53**: PT-1
- **compliance_map / iso_27001**: A.8.11
- **compliance_v2 / hitrust**: 06.d
- **compliance_v2 / cmmc**: MP.L2-3.8.1
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.11

## Run only this check

```
wpsecscan only cookie_banner_cosmetic_vs_blocking https://example.com
```

`only` runs this check alone and prints its findings.
