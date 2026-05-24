# SameSite/WebDAV/PWA/HTTP3/contrast (#B25+B30+B32-B34)

**check_id**: `sri_pwa_misc`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

Round-62 bundle — small one-off checks that don't warrant their own file:

#B25 — cookie SameSite=None enforcement
#B30 — WebDAV LOCK/UNLOCK
#B32 — PWA manifest + Service Worker scope audit
#B33 — HTTP/3 + QUIC presence
#B34 — colour-contrast measurement (best-effort sample of the home CSS)

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: SI-10
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only sri_pwa_misc
```
