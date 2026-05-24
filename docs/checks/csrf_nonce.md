# CSRF / nonce form audit

**check_id**: `csrf_nonce`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

CSRF / WP-nonce audit.

Look at common state-changing endpoints (the login form, comment form, password
reset, REST endpoints) and confirm they're protected by a nonce or token. WP's
nonce field is `_wpnonce`; some plugins use `_token`, `csrfmiddlewaretoken`,
`authenticity_token`, etc.

This is read-only: we GET the page and inspect the rendered form HTML.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
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
wpsecscan --target https://example.com --only csrf_nonce
```
