# WP-Multisite per-blog deep audit (#17)

**check_id**: `wp_multisite_deep`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-RAC

## What it does

Round-60 #17 — WP-Multisite per-blog deep audit.

Enumerates network sites via /wp-json/wp/v2/sites and probes each
sub-blog for: distinct admin users, distinct plugin set, distinct
options, cross-tenant REST data leakage.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.1
- **compliance_v2 / iso_27001_2022**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only wp_multisite_deep
```
