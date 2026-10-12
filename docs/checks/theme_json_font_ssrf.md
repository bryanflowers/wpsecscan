---
id: theme_json_font_ssrf
title: "theme.json font-source SSRF surface (A24)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 141
---

# theme.json font-source SSRF surface (A24)

**check_id**: `theme_json_font_ssrf`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-918
**D3FEND**: D3-NTA

## What it does

A24 (v2.6.0) — theme.json font-source SSRF probe.

Gutenberg 6.2+ accepts a remote `fontFamilies.source` URL in
`theme.json`; that URL is fetched server-side by the WP HTTP API when
the Font Library generates the CSS. Several themes register an admin
endpoint that takes the source URL as a POST parameter, enabling SSRF
to internal hosts (cloud metadata, internal services).

Passive: fingerprint installs that have ANY theme.json setting reachable
via the REST `/wp-json/wp/v2/global-styles/` endpoint. Surface medium
if the global-styles JSON contains a remote fontFamilies.source URL —
that's the operator's CONFIGURED state, which means the SSRF surface
is active.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | theme.json registers remote font-source URL — verify Font Library SSRF guard | 1. Audit any theme endpoint that accepts a font source URL — must validate via wp_http_validate_url() AND check the resolved IP isn't RFC1918/link-local. 2. WP core itself doesn't expose the field publicly; the risk is custom plugin / theme code. 3. Disable wp_http_validate_url filter overrides. |

## Evidence the check records

- theme.json registers remote font-source URL — verify Font Library SSRF guard: REST ⟨path⟩ returned a fontFamilies entry with source = ⟨value⟩ If your theme exposes an admin endpoint that POSTs a user-controlled source URL, an attacker can probe internal hosts via the WP HTTP API.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only theme_json_font_ssrf https://example.com
```

`only` runs this check alone and prints its findings.
