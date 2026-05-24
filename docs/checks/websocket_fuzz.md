# WebSocket frame fuzzer (#23)

**check_id**: `websocket_fuzz`
**aggressive**: yes
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
wpsecscan --target https://example.com --only websocket_fuzz
```
