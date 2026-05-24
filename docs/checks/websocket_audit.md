# WebSocket upgrade + origin audit

**check_id**: `websocket_audit`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WebSocket audit.

Probes for /ws, /wss, /socket.io/, /websocket endpoints. Sends an HTTP/1.1
Upgrade: websocket handshake (using a raw socket since httpx doesn't natively
support WS) and checks:
  1. Whether the endpoint accepts the upgrade
  2. Whether the Origin header is enforced (cross-origin WS = CSRF over WS)
  3. Whether auth is enforced before upgrade

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.21
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only websocket_audit
```
