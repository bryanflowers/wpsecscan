# WordPress core version

**check_id**: `core_version`
**aggressive**: no
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Gather Victim Host Information: Software

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only core_version
```
