# WAF brand deep-detect — 11 vendors (#B23)

**check_id**: `waf_brand_deep`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Round-62 #B23 — WAF brand fingerprinting (deep — beyond round-Q's `waf`).

Adds detection for Imperva (Incapsula), F5 BIG-IP / ASM, Barracuda, NSFOCUS,
ModSecurity CRS version sniff, Citrix NetScaler, FortiWeb, Radware AppWall.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.6
- **compliance_extra / fedramp**: SC-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 13.10
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only waf_brand_deep
```
