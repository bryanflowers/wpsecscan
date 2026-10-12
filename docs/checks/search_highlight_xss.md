---
id: search_highlight_xss
title: "Search-result <mark> reflected XSS (A25)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 89
---

# Search-result <mark> reflected XSS (A25)

**check_id**: `search_highlight_xss`
**aggressive**: no
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript
**CWE**: CWE-79
**D3FEND**: D3-FA

## What it does

A25 (v2.6.0) — Search-result &lt;mark&gt;-highlight XSS probe.

Several search plugins (Relevanssi, SearchWP, plus core ?s= when a
theme wraps results in &lt;mark&gt;) wrap the user's search term in
`<mark>highlight</mark>` for visual emphasis. Many themes do this
without escaping the term first, producing reflected XSS via the `?s=`
query parameter.

Passive: probe `/?s=<svg/onload=alert(1)>` and check whether the
literal `<svg/onload` appears in the response body (unescaped).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Reflected XSS via search-result highlight (?s=) | 1. Open the theme's search.php (or the active search plugin's highlight template) and pass the search term through esc_html() before injecting into &lt;mark&gt;. 2. For Relevanssi specifically, set relevanssi_highlight_no_tags to true OR update to &gt;= 4.22. 3. Until fixed, add a WAF rule blocking &lt;svg / &lt;iframe / &lt;script substrings in ?s= query params. |

## Evidence the check records

- Reflected XSS via search-result highlight (?s=): GET /?s=⟨_PAYLOAD⟩ → HTTP ⟨value⟩ Response body contains the unescaped payload at: ⟨value⟩ Excerpt around the reflection: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only search_highlight_xss https://example.com
```

`only` runs this check alone and prints its findings.
