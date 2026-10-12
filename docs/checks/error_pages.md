---
id: error_pages
title: "Error-page fingerprinting"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 61
---

# Error-page fingerprinting

**check_id**: `error_pages`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software

## What it does

Error-page fingerprinting.

Probe a deliberately-bad URL and inspect the resulting error response for
disclosed server stack: Apache/Nginx version, PHP version, framework
debug-mode indicators (Symfony, Laravel, Django all have characteristic
error pages).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/low | Error page leaks: ⟨name⟩ | For server-version leaks: suppress with `server_tokens off;` (Nginx) or `ServerTokens Prod` + `ServerSignature Off` (Apache). For PHP debug traces: set `display_errors=Off` and `expose_php=Off` in php.ini; in wp-config: `define('WP_DEBUG_DISPLAY', false);` (debug.log only, never to browser). |
| info | Error pages don't leak stack/version info | No action needed. |

## Evidence the check records

- Error pages don't leak stack/version info: Probed ⟨count⟩ bad paths; no version strings or debug traces found.
- Error page leaks: ⟨name⟩: Pattern detected on ⟨count⟩ probed path(s): ⟨sample_lines⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-11
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only error_pages https://example.com
```

`only` runs this check alone and prints its findings.
