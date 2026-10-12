---
id: file_upload
title: "Upload-endpoint probes"
severity_max: critical
severity_dynamic: true
aggressive: true
category: "SSRF / RCE / open access"
words: 97
---

# Upload-endpoint probes

**check_id**: `file_upload`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1505.003 — Web Shell

## What it does

Probe known-vulnerable file-upload endpoints for unauthenticated reachability.

We do NOT actually upload payloads. We just check whether the endpoints
respond as if they would accept an upload (typical signals: 200 with a
specific JSON shape, 400 'no file' error, etc.) — which means an authn
gate is missing.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, low) | Upload endpoint reachable unauthenticated: ⟨desc⟩ | Block this URL via .htaccess / nginx unless required, and require authentication for any endpoint that handles uploads. For wp-file-manager specifically, the legacy elFinder connector should be removed entirely. |
| info | No known upload endpoints reachable unauthenticated | No action needed. |

## Evidence the check records

- No known upload endpoints reachable unauthenticated: Probed ⟨count⟩ known upload endpoints.
- Upload endpoint reachable unauthenticated: ⟨desc⟩: ⟨method⟩ ⟨path⟩ -&gt; HTTP ⟨value⟩ body: ⟨body_snippet⟩ This doesn't confirm an upload succeeded — only that the endpoint responds to anonymous requests. Real exploitation depends on parameter handling inside the endpoint.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SC.L2-3.13.13
- **compliance_v2 / nist_csf**: PR.PS-04
- **compliance_v2 / cis_v8**: 10.5
- **compliance_v2 / iso_27001_2022**: A.8.7

## References

- primary: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- deep dive: https://portswigger.net/web-security/file-upload

## Run only this check

```
wpsecscan only file_upload https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
