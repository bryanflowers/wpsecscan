# Upload-endpoint probes

**check_id**: `file_upload`
**aggressive**: yes
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1505.003 — Web Shell

## What it does

Probe known-vulnerable file-upload endpoints for unauthenticated reachability.

We do NOT actually upload payloads. We just check whether the endpoints
respond as if they would accept an upload (typical signals: 200 with a
specific JSON shape, 400 'no file' error, etc.) — which means an authn
gate is missing.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SC.L2-3.13.13
- **compliance_v2 / nist_csf**: PR.PS-04
- **compliance_v2 / cis_v8**: 10.5
- **compliance_v2 / iso_27001_2022**: A.8.7

## Run only this check

```
wpsecscan --target https://example.com --only file_upload
```
