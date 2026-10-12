---
id: webdav
title: "WebDAV / OPTIONS enumeration"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 70
---

# WebDAV / OPTIONS enumeration

**check_id**: `webdav`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
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

## Request footprint

The module contains 2 request call(s) to the target (REQUEST x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium | WebDAV methods accepted: ⟨value⟩ | Block WebDAV methods at the web server. nginx: `if ($request_method !~ ^(GET\|HEAD\|POST\|OPTIONS)$) { return 405; }`. Apache: `<LimitExcept GET POST HEAD OPTIONS>Require all denied</LimitExcept>`. |
| medium | WebDAV advertised via DAV: ⟨dav⟩ | Disable WebDAV at the web server. nginx: don't include the dav module; Apache: `a2dismod dav dav_fs`. WebDAV on public WP rarely has a legitimate use. |
| info | WebDAV methods rejected | No action. |

## Evidence the check records

- WebDAV advertised via DAV: ⟨dav⟩: OPTIONS / -&gt; DAV: ⟨dav⟩
- WebDAV methods rejected: Probed ⟨count⟩ WebDAV methods; none accepted.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only webdav https://example.com
```

`only` runs this check alone and prints its findings.
