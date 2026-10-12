---
id: server_timing
title: "Server-Timing / debug headers"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 105
---

# Server-Timing / debug headers

**check_id**: `server_timing`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A09:2021 — Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.002 — Software

## What it does

Server-Timing and debug-header leak check.

Modern frameworks add Server-Timing for browser dev-tool perf measurement.
On production it often leaks upstream architecture (cache hits, DB query
counts, framework names). Pair it with X-Request-ID / X-Trace-ID / X-Backend
etc. for a fingerprint surface.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ debug-mode header(s) leaked | Disable debug mode / profiler in production config. Strip these headers at the edge if you need them only for internal observability. |
| low | ⟨count⟩ fingerprint header(s) present | Strip non-essential headers at the web server. Nginx: `more_clear_headers X-Powered-By Server-Timing X-Trace-ID;` (requires headers-more module). |
| info | No Server-Timing / debug-header leaks | No action needed. |

## Evidence the check records

- No Server-Timing / debug-header leaks: None of the ⟨count⟩ known leaky headers present on /.
- ⟨count⟩ debug-mode header(s) leaked: Headers that indicate debug/profiling mode is on in production: ⟨lines⟩ X-Debug-Token-Link in particular often gives anonymous access to the Symfony profiler dashboard.
- ⟨count⟩ fingerprint header(s) present: Headers expose backend stack details: ⟨lines⟩ These help attackers narrow CVE candidates and route traffic predictions.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/ | grep -iE 'server-timing|x-request-id|x-trace-id|x-debug-token|x-backend-server|x-aspnet-version|x-powered-by'
# Strip from Nginx:
# more_clear_headers 'Server-Timing' 'X-Powered-By' 'X-AspNet-Version' 'X-Debug-Token';
# Strip from Apache:
# Header always unset Server-Timing
# Header always unset X-Powered-By
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-11
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only server_timing https://example.com
```

`only` runs this check alone and prints its findings.
