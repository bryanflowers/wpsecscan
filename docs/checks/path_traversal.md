# Path traversal probes

**check_id**: `path_traversal`
**aggressive**: yes
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Path traversal probes on common WP/plugin file-serving endpoints.

Read-only payloads — we look at common parameters used by plugins to serve
files (download=, file=, path=, doc=, etc.) and try classic ../../etc/passwd
patterns. Detection by content signatures (e.g. 'root:x:0:0').

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only path_traversal
```
