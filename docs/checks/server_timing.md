# Server-Timing / debug headers

**check_id**: `server_timing`
**aggressive**: no
**OWASP**: A09:2021 — Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.002 — Software

## What it does

Server-Timing and debug-header leak check.

Modern frameworks add Server-Timing for browser dev-tool perf measurement.
On production it often leaks upstream architecture (cache hits, DB query
counts, framework names). Pair it with X-Request-ID / X-Trace-ID / X-Backend
etc. for a fingerprint surface.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-11
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only server_timing
```
