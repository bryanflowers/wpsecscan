# CSRF nonce entropy sampler

**check_id**: `csrf_entropy`
**aggressive**: no
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

## Run only this check

```
wpsecscan --target https://example.com --only csrf_entropy
```
