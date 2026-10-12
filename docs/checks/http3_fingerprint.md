---
id: http3_fingerprint
title: "HTTP/3 + QUIC fingerprint"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 137
---

# HTTP/3 + QUIC fingerprint

**check_id**: `http3_fingerprint`
**aggressive**: no
**category**: Transport & headers
**max severity**: info
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | HTTP/3 advertised via Alt-Svc⟨value⟩ | Confirm your WAF inspects HTTP/3 traffic (Cloudflare/Fastly do by default; on-prem h3 behind an external WAF may not). Use h2load or curl --http3 to verify the h3 endpoint behaves identically to h2. |
| info | HTTP/3 fingerprint — no response on / | No action. |
| info | HTTP/3 not advertised on / | No action. |

## Evidence the check records

- HTTP/3 fingerprint — no response on /: Couldn't reach / to read Alt-Svc.
- HTTP/3 advertised via Alt-Svc⟨value⟩: Alt-Svc header: ⟨value⟩ Server header: ⟨value⟩ Many WAFs and CDNs apply different rules to h3 traffic — bypass attempts often hit fewer filters over QUIC than over h2. Worth re-running aggressive probes with an h3-capable client.
- HTTP/3 not advertised on /: Alt-Svc header absent or doesn't list h3. Server: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only http3_fingerprint https://example.com
```

`only` runs this check alone and prints its findings.
