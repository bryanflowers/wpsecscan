---
id: tls_headers
title: "TLS & security headers"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "Transport & headers"
words: 201
---

# TLS & security headers

**check_id**: `tls_headers`
**aggressive**: no
**category**: Transport & headers
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1071.001 — Application Layer Protocol: Web Protocols

## What it does

TLS and security-header check.

Fetches / once and looks for six response headers: Strict-Transport-Security
(missing is high), Content-Security-Policy and X-Frame-Options (medium),
X-Content-Type-Options, Referrer-Policy and Permissions-Policy (low). It also
reports Server / X-Powered-By disclosure (low, or info when a CDN or WAF
injects it). For https targets it opens a TLS connection to port 443 and
reports TLS 1.1 or older (high), an expired certificate (critical), expiry in
under 14 days (high), or a failed handshake (medium). A plain-HTTP target is
reported as high. One GET plus one socket handshake.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | TLS certificate has expired | Renew the certificate immediately (Let's Encrypt: `certbot renew`). |
| varies (high, medium, low) | Missing security header: ⟨header⟩ | — |
| high | Outdated TLS version supported: ⟨tls_ver⟩ | Disable TLS &lt; 1.2 in your web server. Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. |
| high | Site is being scanned over plain HTTP | Serve the site over HTTPS only. Get a free cert via Let's Encrypt and redirect HTTP→HTTPS at the server. |
| high | TLS certificate expires soon (⟨days⟩ day(s)) | Renew now; check that auto-renewal is configured and the renew hook reloads the web server. |
| medium | Could not complete TLS handshake for inspection | Verify the cert chain is complete and the server presents a valid SNI cert. |
| medium | Could not fetch / for header inspection | Verify the site is reachable and re-run. |
| low | Server / X-Powered-By headers leak software info | Suppress these headers. Nginx: `more_clear_headers Server X-Powered-By;` (headers-more module) or `server_tokens off;`. PHP: set `expose_php = Off` in php.ini. |
| info | Server header set by upstream CDN (cannot be suppressed at origin) | No action: this header is injected by your CDN/edge, not your web server. Hide it via the CDN's transform/response-header rules if you still want it suppressed. |

## Evidence the check records

- Could not fetch / for header inspection: GET / returned no response (timeout or transport error).
- Missing security header: ⟨header⟩: GET / response did not include ⟨header⟩.
- Server header set by upstream CDN (cannot be suppressed at origin): ⟨value⟩ Detected CDN/WAF: ⟨value⟩
- Could not complete TLS handshake for inspection: Socket-level handshake to ⟨host⟩:443 failed.
- Site is being scanned over plain HTTP: Target URL is ⟨value⟩ (no TLS).
- Outdated TLS version supported: ⟨tls_ver⟩: Connection to ⟨host⟩:443 negotiated ⟨tls_ver⟩.
- TLS certificate has expired: Cert CN=⟨cn⟩; expired ⟨value⟩ day(s) ago.
- TLS certificate expires soon (⟨days⟩ day(s)): Cert CN=⟨cn⟩; expires in ⟨days⟩ day(s).

## Suggested fix

Add baseline security headers (Nginx). Where to apply it: nginx server block.

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options SAMEORIGIN always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self' https:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'" always;
server_tokens off;
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/ | grep -iE 'strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy'
# Deep TLS audit:
ssllabs-scan --quiet https://example.com
# Or in a browser: https://www.ssllabs.com/ssltest/analyze.html?d={host}
```

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-8
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## References

- primary: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

## Run only this check

```
wpsecscan only tls_headers https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
