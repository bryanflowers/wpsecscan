---
id: tls_reneg_dos
title: "TLS renegotiation DoS probe (#26)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 96
---

# TLS renegotiation DoS probe (#26)

**check_id**: `tls_reneg_dos`
**aggressive**: no
**category**: Transport & headers
**max severity**: info
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1499 — Endpoint Denial of Service
**CWE**: CWE-400
**D3FEND**: D3-CH

## What it does

#26 TLS renegotiation DoS probe.

The 2009-vintage CVE-2009-3555 flaw: a server that allows client-initiated
renegotiations can be DoS'd with a single connection that triggers many
renegotiations (server CPU is ~5x client CPU per reneg).

Modern OpenSSL disables this by default; older nginx / Apache / IIS may
still allow it. We probe by negotiating + renegotiating 5x; flag if the
server accepts more than 1.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | TLS reneg DoS skipped (non-HTTPS target) | No action. |
| info | TLS renegotiation DoS — manual test required | If the server accepts &gt;1 client-initiated reneg, add `ssl_session_tickets off;` + `ssl_reuse_sessions off;` to nginx, or upgrade OpenSSL. |

## Evidence the check records

- TLS renegotiation DoS — manual test required: ⟨detail⟩ Verify manually: openssl s_client -connect ⟨host⟩:⟨port⟩ -reconnect 5
- TLS reneg DoS skipped (non-HTTPS target): Target uses HTTP — TLS reneg N/A.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-13
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only tls_reneg_dos https://example.com
```

`only` runs this check alone and prints its findings.
