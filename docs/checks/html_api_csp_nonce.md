---
id: html_api_csp_nonce
title: "WP 6.7 HTML API breaks CSP nonces (O142)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 155
---

# WP 6.7 HTML API breaks CSP nonces (O142)

**check_id**: `html_api_csp_nonce`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1059.007 — JavaScript
**CWE**: CWE-1021
**D3FEND**: D3-FA

## What it does

O142 (v2.6.0) — HTML-API rewriting breaks CSP nonces.

WP 6.7 ships the HTML API for tag-level rewriting in PHP. Themes that
post-process the rendered HTML via `WP_HTML_Tag_Processor::next_tag()`
sometimes drop CSP nonce attributes from inline scripts (the API
preserves attributes by default but custom callbacks can mutate them).

When the page sends a strict CSP with `script-src 'nonce-...'`, any
inline &lt;script&gt; that lost its nonce is blocked at runtime — breaking
functionality silently. Conversely, if a theme INJECTS scripts without
nonces, the operator may be tempted to weaken the CSP to fix it.

Passive: GET /, compare:
  - CSP header script-src directive
  - inline &lt;script&gt; tags' nonce= attribute presence
Flag medium when CSP requires a nonce but some inline scripts lack it.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | CSP requires script nonces but ⟨inline_no_nonce⟩ inline &lt;script&gt; tag(s) have no nonce | 1. Check whether a theme's HTML-API mutator is stripping the nonce attribute (look for WP_HTML_Tag_Processor calls). 2. If injected without nonce: have the theme use wp_get_script_nonce() (or its equivalent) at render time. 3. DO NOT weaken the CSP to 'unsafe-inline' as a workaround — that defeats the whole nonce strategy. |

## Evidence the check records

- CSP requires script nonces but ⟨inline_no_nonce⟩ inline &lt;script&gt; tag(s) have no nonce: CSP header includes nonce-... directive. Inline &lt;script&gt; tags WITH nonce: ⟨inline_with_nonce⟩ Inline &lt;script&gt; tags WITHOUT nonce: ⟨inline_no_nonce⟩ Examples (first 5): ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.27

## Run only this check

```
wpsecscan only html_api_csp_nonce https://example.com
```

`only` runs this check alone and prints its findings.
