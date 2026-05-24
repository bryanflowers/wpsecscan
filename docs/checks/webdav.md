# WebDAV / OPTIONS enumeration

**check_id**: `webdav`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-650
**D3FEND**: D3-NTA

## What it does

WebDAV / extended HTTP method enumeration.

Probes for `PROPFIND`, `MOVE`, `COPY`, `MKCOL` against the site root. These
methods indicate WebDAV is enabled. WebDAV on a public site is almost always
a misconfiguration — it allows file upload, move, and listing without auth
if the server is set up wrong.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only webdav
```
