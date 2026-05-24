# Directory listing

**check_id**: `directory_listing`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L1-3.1.20
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan --target https://example.com --only directory_listing
```
