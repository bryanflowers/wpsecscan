# HTTP/3 + QUIC fingerprint

**check_id**: `http3_fingerprint`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

H3 HTTP/3 + QUIC fingerprint.

Detects whether the target advertises HTTP/3 via `Alt-Svc: h3="..."` and
identifies the QUIC implementation by reading the server header alongside.
HTTP/3-capable proxies (Cloudflare, Fastly, Caddy, LiteSpeed) advertise
themselves consistently — knowing which one matters for picking the right
WAF-bypass payloads.

This is a passive header sniff; no QUIC handshake is performed (would need
aioquic, an optional dep we don't want to require).

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only http3_fingerprint
```
