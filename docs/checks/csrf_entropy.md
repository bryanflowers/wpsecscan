---
id: csrf_entropy
title: "CSRF nonce entropy sampler"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 143
---

# CSRF nonce entropy sampler

**check_id**: `csrf_entropy`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-330
**D3FEND**: D3-MFA

## What it does

H5 CSRF / nonce entropy sampler.

WordPress nonces are PHP `wp_create_nonce()` outputs — short (10 chars)
and short-lived (12-24h). If a custom plugin generates its own nonces
with poor entropy (predictable, low-bit, or simple counter), the value
becomes guessable and CSRF defense collapses.

We sample N nonce values from the homepage (and a few common endpoints
that re-render forms), then compute:
  - Shannon entropy across the sample
  - Repetition rate (any collision → fatal)
  - Character-class diversity

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium/low/info | CSRF nonce entropy concerns (⟨count⟩ issue(s)) | If you have a custom plugin generating CSRF tokens, switch to `wp_create_nonce($action)` (WP core, uses sha1 of session + action + user). Never use `time()` or a counter. |
| info | CSRF nonce entropy looks healthy (⟨count⟩ unique samples) | No action. |
| info | CSRF nonce entropy — no nonces sampled | No action. |

## Evidence the check records

- CSRF nonce entropy — no nonces sampled: The homepage and login page didn't expose `_wpnonce` values; either none in HTML or the site uses a custom anti-CSRF mechanism.
- CSRF nonce entropy concerns (⟨count⟩ issue(s)): Sampled ⟨count⟩ nonces across the site. ⟨value⟩ Sample nonces (first 5): ⟨value⟩
- CSRF nonce entropy looks healthy (⟨count⟩ unique samples): Avg length ⟨avg_len⟩, avg entropy ⟨avg_entropy⟩ bits/char, 0% repetition.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-13
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: SI-10
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.h
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.25

## References

- primary: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Run only this check

```
wpsecscan only csrf_entropy https://example.com
```

`only` runs this check alone and prints its findings.
