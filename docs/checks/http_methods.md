---
id: http_methods
title: "HTTP method enumeration"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 56
---

# HTTP method enumeration

**check_id**: `http_methods`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

HTTP method enumeration — checks OPTIONS, TRACE, PUT, DELETE, PATCH.

## Request footprint

The module contains 2 request call(s) to the target (REQUEST x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium | ⟨count⟩ dangerous HTTP method(s) appear accepted | Disable unsafe methods at the server level. Nginx: `if ($request_method !~ ^(GET\|POST\|HEAD\|OPTIONS)$) { return 405; }`. Apache: `<LimitExcept GET POST HEAD OPTIONS>Require all denied</LimitExcept>`. TRACE in particular enables Cross-Site Tracing if you have any reflective vulns elsewhere. |
| info | No dangerous HTTP methods accepted | No action needed. |
| info | OPTIONS / advertises methods: ⟨allow⟩ | No action unless dangerous methods are listed (see below). |

## Evidence the check records

- ⟨count⟩ dangerous HTTP method(s) appear accepted: ⟨lines⟩ Methods returning 2xx/3xx implies the server is handling them rather than rejecting with 405.
- No dangerous HTTP methods accepted: Probed ⟨count⟩ methods; all rejected.
- OPTIONS / advertises methods: ⟨allow⟩: Allow: ⟨allow⟩

## Suggested fix

Block dangerous HTTP methods (Nginx). Where to apply it: nginx server block.

```nginx
if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sX OPTIONS https://example.com/ -i | grep -i allow
curl -sX TRACE https://example.com/ -i
curl -sX PUT https://example.com/ -i | head -5
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only http_methods https://example.com
```

`only` runs this check alone and prints its findings.
