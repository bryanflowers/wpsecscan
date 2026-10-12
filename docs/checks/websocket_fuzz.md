---
id: websocket_fuzz
title: "WebSocket frame fuzzer (#23)"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "GraphQL & APIs"
words: 130
---

# WebSocket frame fuzzer (#23)

**check_id**: `websocket_fuzz`
**aggressive**: yes
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-345
**D3FEND**: D3-IVA

## What it does

#23 (from ZAP) — WebSocket frame fuzzer.

For sites that expose a WebSocket endpoint (auto-discovered from HTML
`new WebSocket(...)` literals), establishes a connection and sends a
small set of malformed / oversized frames to surface crashes,
authorisation slips, or content reflection.

Uses `websockets` if installed; otherwise emits an install hint.

Frames sent:
  - oversized payload (1 MB of `A`)
  - malformed JSON (`{"id":`)
  - prototype-pollution-style key (`{"__proto__":{"polluted":1}}`)
  - SQL-meta in a free-text field (`'OR'1'='1`)
  - script-tag XSS (`<svg/onload=alert(1)>`)

Aggressive only.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WebSocket ⟨u⟩ — ⟨count⟩ suspicious response(s) | Audit the WebSocket message handler. Treat every inbound message as untrusted input — schema-validate (Ajv / jsonschema) before any DB or filesystem operation. Add per-connection auth checks; don't assume the Sec-WebSocket-Origin header has been validated. |
| info | WebSocket fuzz skipped (passive mode) | No action. |
| info | WebSocket fuzz skipped (websockets not installed) | No action. |
| info | WebSocket fuzz — no endpoints found in homepage HTML | No action. |
| info | WebSocket fuzz — ⟨count⟩ endpoint(s) tested, no issues | No action. |

## Evidence the check records

- WebSocket fuzz skipped (passive mode): Pass --aggressive to enable.
- WebSocket fuzz skipped (websockets not installed): Install: `pip install websockets`
- WebSocket fuzz — no endpoints found in homepage HTML: No `new WebSocket(...)` / `wss?://...` literals on /.
- WebSocket fuzz — ⟨count⟩ endpoint(s) tested, no issues: Endpoints: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only websocket_fuzz https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
