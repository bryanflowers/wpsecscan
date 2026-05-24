# Cloud-metadata SSRF chain (needs SSRF candidate)

**check_id**: `cloud_metadata_ssrf`
**aggressive**: yes
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
**CWE**: CWE-918
**D3FEND**: D3-NTA

## What it does

H1 Cloud-metadata SSRF chain.

If a previous SSRF check confirmed the target fetches attacker-controlled URLs,
this check escalates by asking the server to fetch cloud-metadata endpoints for
AWS / GCP / Azure / DigitalOcean / Hetzner / Oracle / Alibaba. A reply that
mirrors the metadata format is proof the server can be used as a confused
deputy to exfiltrate IAM tokens.

Aggressive only — runs ONLY when the ssrf check has already flagged a confirmed
or suspected SSRF parameter (avoids blind probing of every URL parameter).

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.6
- **compliance_extra / fedramp**: SC-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## Run only this check

```
wpsecscan --target https://example.com --only cloud_metadata_ssrf
```
