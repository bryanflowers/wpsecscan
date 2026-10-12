---
id: csp
title: "CSP deep analysis"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 71
---

# CSP deep analysis

**check_id**: `csp`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1059.007 — Command and Scripting: JavaScript

## What it does

Deep CSP analysis.

The tls_headers check flags a missing CSP. This one *grades* a present CSP —
scoring usage of unsafe-inline, unsafe-eval, wildcard sources, and missing
directives that meaningfully harden the page.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium/low | CSP has ⟨count⟩ weakness(es) | Tighten the CSP: remove 'unsafe-inline' / 'unsafe-eval' (use nonces or hashes); set `object-src 'none'`, `frame-ancestors 'self'`, `base-uri 'self'`. Start in report-only mode (`Content-Security-Policy-Report-Only`) to measure breakage before enforcing. |
| info | CSP is reasonably hardened | No action needed. |
| info | No Content-Security-Policy header present (deep grading skipped) | Adding a baseline CSP — even `default-src 'self' https:; object-src 'none'; frame-ancestors 'self'` — blocks the most common XSS payloads. |

## Evidence the check records

- No Content-Security-Policy header present (deep grading skipped): See the 'TLS & security headers' check for the basic header-presence finding.
- CSP is reasonably hardened: Policy: ⟨value⟩⟨value⟩
- CSP has ⟨count⟩ weakness(es): Policy: ⟨value⟩⟨value⟩ Issues: ⟨value⟩

## Suggested fix

Tighter CSP (Apache). Where to apply it: .htaccess (root).

```apache
Header set Content-Security-Policy "default-src 'self' https:; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'"
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/ | grep -i content-security-policy
# Mozilla Observatory grades your overall header config:
https://observatory.mozilla.org/analyze/{host}
# CSP-specific evaluator:
https://csp-evaluator.withgoogle.com/
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.23

## References

- primary: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- deep dive: https://csp.withgoogle.com/docs/index.html

## Run only this check

```
wpsecscan only csp https://example.com
```

`only` runs this check alone and prints its findings.
