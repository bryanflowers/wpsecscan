# Server-stack reveal + PHP EOL detect (#B22+B29)

**check_id**: `server_stack_reveal`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Round-62 #B22, #B29 — server-side stack reveal + PHP version detect.

Parses every banner-style header WordPress + nginx/Apache + PHP-FPM commonly
leak, then maps versions against EOL data to flag end-of-life software.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_extra / hipaa**: 164.308(a)(1)
- **compliance_extra / soc2**: CC7.1
- **compliance_extra / fedramp**: SI-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: CM.L2-3.4.6
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only server_stack_reveal
```
