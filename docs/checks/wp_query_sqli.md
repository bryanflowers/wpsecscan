# WP_Query/wpdb-specific SQLi (#4)

**check_id**: `wp_query_sqli`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-89
**D3FEND**: D3-IVA

## What it does

#4 WP_Query / $wpdb-specific SQLi probes.

Targets WordPress-specific quirks the generic sqli check doesn't:
  - %d-formatted columns receiving non-numeric input (wpdb::prepare quirk)
  - $wpdb->prepare('LIKE %s', ...) where the value contains %% / _ /   - meta_query parameter pollution
  - tax_query parameter pollution

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only wp_query_sqli
```
