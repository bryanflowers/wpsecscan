---
id: global_styles_css_injection
title: "FSE global-styles CSS-inject probe (F10)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 94
---

# FSE global-styles CSS-inject probe (F10)

**check_id**: `global_styles_css_injection`
**aggressive**: no
**category**: Injection & client-side
**max severity**: low
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript
**CWE**: CWE-79
**D3FEND**: D3-NTA

## What it does

F10 (v2.8.1) — FSE global-styles CSS injection probe.

Full Site Editing themes (WP 5.9+) accept user-supplied CSS via
`/wp-json/wp/v2/global-styles/<id>`. Update permission is normally
gated on `edit_theme_options`, but several theme + plugin combos
expose write access more broadly. We probe the read endpoint and
flag if the JSON contains user-defined CSS that could be tampered
with via an under-protected UPDATE endpoint.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | F10: FSE global-styles endpoint is publicly readable | Verify only `edit_theme_options` users can PATCH /wp-json/wp/v2/global-styles/&lt;id&gt;. Audit FSE-theme code for any `register_rest_route` callbacks that lower the bar. |

## Evidence the check records

- F10: FSE global-styles endpoint is publicly readable: GET /wp-json/wp/v2/global-styles returned 200. If write permission is similarly relaxed, an attacker could inject arbitrary CSS into every page (phishing-overlay, login-form spoofing, CSP-bypass via background-url exfil).

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
wpsecscan only global_styles_css_injection https://example.com
```

`only` runs this check alone and prints its findings.
