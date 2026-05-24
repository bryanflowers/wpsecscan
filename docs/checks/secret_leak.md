# Accidental API-key leak scan

**check_id**: `secret_leak`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Unsecured Credentials: Credentials in Files

## What it does

Accidental secret-leak detection.

Scans page bodies for patterns that look like API keys / tokens left in
the HTML or in JS files. WordPress sites frequently leak Stripe keys,
Google Maps API keys, Mailchimp keys, etc. when developers build client-side
configs directly into the page.

Detection is regex-based; we redact the matched value before placing it in
the finding so the report itself doesn't leak the secret.

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-28
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: IA-5
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.a
- **compliance_v2 / cmmc**: IA.L2-3.5.10
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.10

## Run only this check

```
wpsecscan --target https://example.com --only secret_leak
```
