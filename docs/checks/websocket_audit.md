---
id: websocket_audit
title: "WebSocket upgrade + origin audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 120
---

# WebSocket upgrade + origin audit

**check_id**: `websocket_audit`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: high
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

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | WebSocket ⟨path⟩ accepts cross-origin upgrade | Validate the Origin header in the WebSocket handler. For the standard WordPress plugins that ship WS (real-time chat, live notifications): check the plugin author's docs for Origin-pinning. Reference: https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking |
| medium | WebSocket endpoint(s) reachable: ⟨value⟩ | Audit the plugin code: the WS handler should call `wp_get_current_user()` or equivalent. |
| info | No WebSocket endpoints reachable at common paths | No action. |

## Evidence the check records

- No WebSocket endpoints reachable at common paths: Probed: ⟨value⟩
- WebSocket ⟨path⟩ accepts cross-origin upgrade: Handshake from `Origin: https://wpsec-evil.example.com` was accepted (HTTP 101). An attacker can mint a WebSocket from a malicious origin and the server won't reject the connection — that's CSWSH (cross-site WebSocket hijacking).
- WebSocket endpoint(s) reachable: ⟨value⟩: Endpoint accepted the upgrade — verify the WS handler enforces auth before exposing data.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.21
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## References

- https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking

## Run only this check

```
wpsecscan only websocket_audit https://example.com
```

`only` runs this check alone and prints its findings.
