---
id: tls_modern
title: "TLS modern features: 0-RTT replay-risk + OCSP stapling + must-staple"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 337
---

# TLS modern features: 0-RTT replay-risk + OCSP stapling + must-staple

**check_id**: `tls_modern`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1573.002 — Encrypted Channel: Asymmetric Cryptography
**CWE**: CWE-326
**D3FEND**: D3-CH

## What it does

Items #21 + #22 — modern TLS feature audit.

#21 — TLS 1.3 0-RTT (Early-Data). 0-RTT allows the client to send
     application data on the FIRST flight, before the handshake
     completes. The server cannot tell whether the data is being
     replayed by an on-path attacker — a real risk for state-changing
     POST requests. WP admin endpoints reachable via 0-RTT are a
     replay-attack vector.

#22 — OCSP stapling + must-staple. Stapling lets the server proactively
     prove cert non-revocation in the handshake; must-staple makes
     clients require it. Without stapling, browsers must do a fallback
     OCSP query, leaking the visitor's IP to the CA and slowing the
     connection.

Implementation: shells out to `openssl s_client` when available
(every modern OS has it). Falls back to a single Python `ssl`
handshake when not — in that case 0-RTT detection is skipped (it's
not exposed at the Python ssl level) and we only report whether the
server negotiates TLS 1.3 successfully.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | TLS 1.3 0-RTT (Early Data) enabled on ⟨host⟩ | Disable 0-RTT at the web server unless every state-changing endpoint is genuinely idempotent. Nginx: `ssl_early_data off;` (default). Cloudflare: Dashboard → SSL/TLS → Edge Certificates → 0-RTT Connection Resumption → Off. If you need 0-RTT for performance, add anti-replay caches on the application side (e.g. nonce-bound CSRF tokens that can only be used once). |
| low | OCSP stapling NOT enabled on ⟨host⟩ | Enable OCSP stapling at the web server: • nginx: `ssl_stapling on; ssl_stapling_verify on;` + a valid `resolver` directive. • Apache: `SSLUseStapling on` + `SSLStaplingCache` directive. • Cloudflare-fronted sites get stapling automatically; verify you're not unproxying the origin. |
| info | OCSP stapling enabled on ⟨host⟩ | No action needed. |
| info | TLS 1.3 negotiated on ⟨host⟩ (openssl unavailable for deeper probe) | For a deeper handshake audit install OpenSSL on the scanner host. Alternatively use a public scanner like https://www.ssllabs.com/ssltest/ to verify OCSP stapling, must-staple, and 0-RTT. |
| info | TLS audit — openssl s_client timed out | No action. |
| info | TLS modern-feature audit completed without findings | No action needed. |
| info | TLS modern-feature audit skipped (non-HTTPS target) | No action. |
| info | TLS must-staple extension present on ⟨host⟩ | No action needed. |

## Evidence the check records

- TLS modern-feature audit skipped (non-HTTPS target): target: ⟨target⟩
- TLS modern-feature audit completed without findings: Probed ⟨host⟩:⟨port⟩.
- OCSP stapling NOT enabled on ⟨host⟩: openssl s_client -status reported `OCSP response: no response sent`. Visitors will fall back to direct OCSP queries to the CA — slower connections + visitor-IP leakage to the CA.
- TLS must-staple extension present on ⟨host⟩: Certificate carries the TLS Feature: status_request extension (must-staple).
- TLS 1.3 0-RTT (Early Data) enabled on ⟨host⟩: Server's TLS 1.3 handshake advertises the `early_data` extension. Clients can send application data on the FIRST flight before the handshake completes. An on-path attacker can REPLAY captured 0-RTT data — a real concern for state-changing endpoints (POST /wp-admin/admin-ajax.php, wp-login, REST mutations).
- TLS audit — openssl s_client timed out: openssl s_client ⟨host⟩:⟨port⟩ did not return within 10s.
- OCSP stapling enabled on ⟨host⟩: openssl s_client -status returned a stapled OCSP response.
- TLS 1.3 negotiated on ⟨host⟩ (openssl unavailable for deeper probe): Negotiated ⟨ver⟩. OCSP stapling + 0-RTT detection require the openssl s_client binary, which was not found on PATH on the scanner host.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.24

## References

- https://www.ssllabs.com/ssltest/

## Run only this check

```
wpsecscan only tls_modern https://example.com
```

`only` runs this check alone and prints its findings.
