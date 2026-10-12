---
id: block_style_variations_url
title: "Block-style URL-prop SSRF (O145)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 80
---

# Block-style URL-prop SSRF (O145)

**check_id**: `block_style_variations_url`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-918
**D3FEND**: D3-NTA

## What it does

O145 (v2.6.0) — Block-Style-Variations URL-prop SSRF.

Gutenberg 16+ block-style variations can carry URL-shaped properties
(e.g. a background-image URL) that the theme renders server-side via
PHP `file_get_contents` or similar. Mis-validated themes have allowed
the URL to point at internal hosts.

Passive: read the rendered HTML for `data-wp-style-*` and inline-style
`url(http://...)` references; flag when any URL points to an internal-
looking host (localhost, 127.0.0.1, 169.254.169.254, RFC1918 ranges).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Block-style URL points to internal host(s): ⟨count⟩ | 1. Find the block style or block-style variation that emits these URLs (Customizer → Additional CSS, or theme.json). 2. Replace with public URLs OR remove if leftover from staging. 3. Internal URLs in CSS can be leveraged for cache-poisoning or SSRF (when a plugin processes the resolved URL server-side). |

## Evidence the check records

- Block-style URL points to internal host(s): ⟨count⟩: Internal-host URLs found in rendered CSS/HTML: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only block_style_variations_url https://example.com
```

`only` runs this check alone and prints its findings.
