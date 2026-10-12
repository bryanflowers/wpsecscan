---
id: interactivity_api_directive_xss
title: "WP 6.5+ Interactivity API directive-XSS probe (F66)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 138
---

# WP 6.5+ Interactivity API directive-XSS probe (F66)

**check_id**: `interactivity_api_directive_xss`
**aggressive**: no
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript
**CWE**: CWE-79
**D3FEND**: D3-NTA

## What it does

F66 (v2.8.3) — WP 6.5+ Interactivity API directive-XSS surface.

The Interactivity API (`@wordpress/interactivity`) renders dynamic
behavior via `data-wp-on`, `data-wp-bind`, and `data-wp-context`
directives. Custom block plugins that interpolate user-controlled
strings into these directive values without HTML-escaping create a
real XSS vector (the directive value is parsed as a JS expression).

This check is DEFENSIVE: we GET the homepage with a URL canary, look
for the canary surfacing inside a `data-wp-*` directive value, and
emit a high-severity finding if found. We do NOT attempt to bypass
sanitization — we just verify whether the page's directive surface
is reflection-aware.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | F66: Interactivity API directive reflects URL input without escaping | Audit your block plugin's directive-binding code. Run any user-controlled string through `wp_kses_post()` (PHP) or `escape-html` (JS) BEFORE interpolating into a `data-wp-*` attribute. The Interactivity API parses directive values as JS expressions; unescaped strings become injection vectors. |
| info | F66: Interactivity API not detected (no data-wp-* attrs) | No action needed; check only applies to WP 6.5+ FSE/Block sites that opted into the Interactivity API. |

## Evidence the check records

- F66: Interactivity API not detected (no data-wp-* attrs): None of the 3 probe responses contained any `data-wp-` directive.
- F66: Interactivity API directive reflects URL input without escaping: GET ⟨path⟩ → canary ⟨_CANARY⟩ appears verbatim inside a `data-wp-*` directive value: `⟨value⟩`

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan only interactivity_api_directive_xss https://example.com
```

`only` runs this check alone and prints its findings.
