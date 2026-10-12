---
id: crlf_location_injection
title: "CRLF injection in Location header (redirect endpoints)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 198
---

# CRLF injection in Location header (redirect endpoints)

**check_id**: `crlf_location_injection`
**aggressive**: no
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-93
**D3FEND**: D3-IAA

## What it does

Item #4 — CRLF injection into Location headers on common WP redirect
endpoints.

The misc_injection_audit check already probes response *bodies* for a
generic CRLF marker, but only when --aggressive is set. CRLF in a
`Location:` header is a higher-value, low-cost passive probe worth
running on every scan: a successful injection lets an attacker plant a
`Set-Cookie` header on every visitor's first redirect (session fixation)
or smuggle a second response.

This check sends a small, throttled payload that — if naively echoed
into a Location header — would introduce a `Set-Cookie: wpsecscan-crlf-probe=1`
follower. We never look at the response *body*; we only inspect the
response's `Location` header (and `Set-Cookie` if present) for the
injected line. The probe is read-only.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | CRLF injection in Location header (⟨count⟩ endpoint(s)) | Reject any `redirect_to` / `returnurl` / `next` value whose decoded form contains `\r` or `\n`. WordPress core's `wp_safe_redirect()` + `wp_validate_redirect()` already do this, so the most common cause is a plugin or theme that builds Location values by string-concat. Add `wp_validate_redirect()` around any custom redirect logic and ensure your reverse proxy strips CR/LF from header values. |
| info | CRLF Location injection — clean (⟨probed⟩ endpoint(s) probed) | No action needed. |

## Evidence the check records

- CRLF injection in Location header (⟨count⟩ endpoint(s)): An attacker-controllable redirect parameter is reflected into the `Location` header without stripping CR/LF. This lets the attacker inject arbitrary follower headers — most commonly `Set-Cookie` for session fixation or HTTP-response splitting: ⟨value⟩
- CRLF Location injection — clean (⟨probed⟩ endpoint(s) probed): Sent a CRLF-laden redirect payload at common WP redirect parameters (`redirect_to`, `returnurl`, `next`, `url`, ...). None of the responses contained the injected `Set-Cookie` follower or raw CR/LF inside the Location header.

## Compliance mapping

- **compliance_map / pci_dss**: 6.5.7
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only crlf_location_injection https://example.com
```

`only` runs this check alone and prints its findings.
