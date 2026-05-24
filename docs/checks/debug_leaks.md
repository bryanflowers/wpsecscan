# Debug & info leaks

**check_id**: `debug_leaks`
**aggressive**: no
**OWASP**: A09:2021 — Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.004 — Gather Victim Host Information: Client Configurations

## Compliance mapping

- **compliance_map / pci_dss**: 10.2.1
- **compliance_map / nist_800_53**: AU-3
- **compliance_map / iso_27001**: A.8.15
- **compliance_v2 / hitrust**: 10.g
- **compliance_v2 / cmmc**: SI.L1-3.14.1
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 4.1
- **compliance_v2 / iso_27001_2022**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only debug_leaks
```
