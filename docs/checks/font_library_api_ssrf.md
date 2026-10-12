---
id: font_library_api_ssrf
title: "WP 6.5 Font Library SSRF audit (O143)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 119
---

# WP 6.5 Font Library SSRF audit (O143)

**check_id**: `font_library_api_ssrf`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: low
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-918
**D3FEND**: D3-NTA

## What it does

O143 (v2.6.0) — Font Library API SSRF audit.

WP 6.5 added the Font Library at /wp-json/wp/v2/font-families. The
endpoint accepts font-collection JSON with a `src` URL; on install,
WordPress fetches the URL server-side via wp_remote_get. Bug history:

  • Pre-6.5.5 installs accepted any URL including file://, http://
    internal, ftp:// → classic SSRF.
  • The `permission_callback` requires `edit_theme_options`, but
    several plugins added a passthrough endpoint that lowers the bar.

Passive: probe the route, observe auth requirement. Surface info
when properly auth-gated, low when 200 (Font Library config readable
unauth).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | WP Font Library endpoint readable unauthenticated: ⟨path⟩ | 1. Confirm WordPress core &gt;= 6.5.5 (SSRF patch). 2. Find which plugin overrides the rest_authentication filter / lowers the font-family endpoint permission. 3. Audit any custom font-source URL in the install — those are pre-validated server-fetched and must be HTTPS public URLs only (no file:// / http:// internal). |

## Evidence the check records

- WP Font Library endpoint readable unauthenticated: ⟨path⟩: GET ⟨path⟩ → HTTP 200. Font Library reads are typically auth-gated to edit_theme_options. An anonymous 200 suggests a custom plugin / mu-plugin lowered the permission.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only font_library_api_ssrf https://example.com
```

`only` runs this check alone and prints its findings.
