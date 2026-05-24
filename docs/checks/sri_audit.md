# Subresource Integrity (SRI) audit (#B24)

**check_id**: `sri_audit`
**aggressive**: no
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1195.002 — Compromise Software Supply Chain
**CWE**: CWE-353
**D3FEND**: D3-SCM

## What it does

Round-62 #B24 — Subresource Integrity (SRI) audit.

For every <script src> and <link rel="stylesheet" href> from a different
origin, check whether `integrity=` is set. Missing SRI on a CDN resource
means an attacker controlling the CDN (or successful BGP hijack / cache
poisoning) can swap the code for arbitrary JS/CSS.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SI-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.h
- **compliance_v2 / cmmc**: SI.L2-3.14.6
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only sri_audit
```
