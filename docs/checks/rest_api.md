# WP REST API surface audit

**check_id**: `rest_api`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WordPress REST API surface audit.

Probes /wp-json/ and common REST endpoints beyond /users (which the existing
users check covers). Flags exposed data the site owner may not realize is
publicly readable.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L1-3.1.20
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan --target https://example.com --only rest_api
```
