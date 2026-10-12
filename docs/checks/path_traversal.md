---
id: path_traversal
title: "Path traversal probes"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 94
---

# Path traversal probes

**check_id**: `path_traversal`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Path traversal probes on common WP/plugin file-serving endpoints.

Read-only payloads — we look at common parameters used by plugins to serve
files (download=, file=, path=, doc=, etc.) and try classic ../../etc/passwd
patterns. Detection by content signatures (e.g. 'root:x:0:0').

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Path traversal confirmed via ⟨desc⟩ | Locate the plugin handling this parameter and patch immediately — validate file paths against realpath() and a known-safe base directory, never concatenate user input into file paths. Take the site offline until fixed; assume any file in the WP install may have been read. |
| critical | Path traversal: wp-config.php contents leaked via ⟨desc⟩ | Patch the plugin immediately and rotate DB credentials, salts, and any API keys in wp-config.php. Audit access logs for prior reads of this URL. |
| info | No path-traversal indicators on tested parameters | No action needed for the tested endpoints. |

## Evidence the check records

- No path-traversal indicators on tested parameters: Probed ⟨value⟩ payloads across ⟨count⟩ parameter patterns.
- Path traversal confirmed via ⟨desc⟩: GET ⟨path⟩ with ⟨param⟩=⟨payload⟩ -&gt; HTTP ⟨value⟩ Response body contains /etc/passwd content (root:x:0:0).
- Path traversal: wp-config.php contents leaked via ⟨desc⟩: GET ⟨path⟩ with ⟨param⟩=⟨payload⟩ Response contains PHP source — wp-config.php was likely served as plaintext.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/www-community/attacks/Path_Traversal
- deep dive: https://portswigger.net/web-security/file-path-traversal

## Run only this check

```
wpsecscan only path_traversal https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
