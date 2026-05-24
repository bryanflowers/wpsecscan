# Privacy/GDPR data + tracker inventory (#16-23)

**check_id**: `privacy_inventory`
**aggressive**: no
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1593 — Search Open Websites
**CWE**: CWE-359
**D3FEND**: D3-NTA

## What it does

Round-59 #16-23 — Privacy / GDPR data inventory + tracker audit.

#16 PII inventory — scan home page + checkout for visible PII fields
   (name/email/phone/address/credit-card patterns) so the data-map is
   one click rather than a manual walkthrough.
#17 Cookie-banner audit — is one present? does it block cookies before
   consent, or is it the cosmetic kind that ePrivacy regulators fine?
#18 Third-party JS exfil — list every third-party script src and the
   data they POST to (sample of inline `fetch(...)` strings).
#19 Google Fonts CJEU check — `fonts.googleapis.com` hits = the
   prohibited-without-consent pattern (per the German ruling).
#20 IP anonymisation — does `_gtag('config', {anonymize_ip: true})`
   appear in any inline script that loads GA/GA4?
#21 DPA helper — emit a structured list of every third-party processor
   detected, so the DPO can issue Data-Processing Agreements quickly.
#22 RTBE (right-to-be-erased) endpoint — is wp-admin/erase-personal-data
   reachable + correctly capability-gated?
#23 International data transfer — for every third-party processor,
   guess the jurisdiction (US/EU/UK) so transfer-impact assessment is
   one click.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: PT-3
- **compliance_map / iso_27001**: A.5.34
- **compliance_extra / hipaa**: 164.524
- **compliance_extra / soc2**: C1.1
- **compliance_extra / fedramp**: PT-3
- **compliance_extra / gdpr**: Article 30
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: MP.L1-3.8.3
- **compliance_v2 / nist_csf**: GV.OC-04
- **compliance_v2 / cis_v8**: 3.1
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan --target https://example.com --only privacy_inventory
```
