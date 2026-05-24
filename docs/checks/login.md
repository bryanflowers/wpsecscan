# Login surface

**check_id**: `login`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.001 — Brute Force: Password Guessing

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.1
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(d)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: IA-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L1-3.5.1
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan --target https://example.com --only login
```
