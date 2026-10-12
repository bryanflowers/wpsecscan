---
id: cors
title: "CORS misconfiguration"
severity_max: high
severity_dynamic: true
aggressive: false
category: "Transport & headers"
words: 113
---

# CORS misconfiguration

**check_id**: `cors`
**aggressive**: no
**category**: Transport & headers
**max severity**: high (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

CORS misconfiguration check.

Send Origin: evil header on a few endpoints and check whether the server
reflects it into Access-Control-Allow-Origin, especially in combination
with Access-Control-Allow-Credentials: true.

The dangerous combo: ACAO reflects attacker origin + ACAC=true → any
malicious page can read authenticated responses from the WP site.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium/low/info | ⟨title_prefix⟩ at ⟨path⟩ | Use an EXPLICIT allow-list. Reject `null` entirely. Never reflect the request Origin without validating against a static list. |
| info | No CORS reflection observed | No action needed. |
| varies | ⟨value⟩ | Use an explicit allow-list of trusted origins, never reflect the Origin header. For plugin-controlled CORS, audit the rest_pre_serve_request filter and any CORS-handling plugin. Server-level (Nginx): explicit static `add_header Access-Control-Allow-Origin https://trusted-origin.com always;`. |

## Evidence the check records

- ⟨value⟩: GET ⟨value⟩ with Origin: ⟨PROBE_ORIGIN⟩ Access-Control-Allow-Origin: ⟨value⟩ Access-Control-Allow-Credentials: ⟨value⟩ Attacker-origin reflection + credentials = any malicious page can read authenticated responses. Wildcard + credentials is rejected by browsers but honored by some non-browser clients.
- ⟨title_prefix⟩ at ⟨path⟩: OPTIONS ⟨path⟩ with Origin: ⟨origin⟩ Access-Control-Allow-Origin: ⟨acao⟩ ⟨value⟩
- No CORS reflection observed: Probed ⟨count⟩ endpoints (simple GET) + ⟨count⟩×2 preflight matrix; none reflected attacker origins.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI -H 'Origin: https://evil.example.com' https://example.com/
# Look at Access-Control-Allow-Origin in the response
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.8.21

## References

- primary: https://portswigger.net/web-security/cors
- deep dive: https://book.hacktricks.xyz/pentesting-web/cors-bypass
- https://wpsecscan-cors-probe.invalid
- https://trusted-origin.com

## Run only this check

```
wpsecscan only cors https://example.com
```

`only` runs this check alone and prints its findings.
