# GDPR/ePrivacy cookie-consent audit

**check_id**: `cookie_consent`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

GDPR / ePrivacy cookie-consent audit.

Loads the homepage WITHOUT any consent (fresh browser equivalent) and checks:
  1. Are non-essential cookies set on first page load? (analytics, marketing,
     third-party tracking) — that's a GDPR/ePrivacy violation in the EU.
  2. Is there a visible cookie banner in the HTML (heuristic)?

We don't try to BLOCK / accept the banner — we just check the cookies that
arrive on the first request and the presence of a banner in the rendered HTML.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: PT-3
- **compliance_map / iso_27001**: A.5.34
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: MP.L1-3.8.3
- **compliance_v2 / nist_csf**: GV.OC-04
- **compliance_v2 / cis_v8**: 3.1
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan --target https://example.com --only cookie_consent
```
