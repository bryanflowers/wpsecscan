---
id: csrf_nonce
title: "CSRF / nonce form audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 138
---

# CSRF / nonce form audit

**check_id**: `csrf_nonce`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

CSRF / WP-nonce audit.

Look at common state-changing endpoints (the login form, comment form, password
reset, REST endpoints) and confirm they're protected by a nonce or token. WP's
nonce field is `_wpnonce`; some plugins use `_token`, `csrfmiddlewaretoken`,
`authenticity_token`, etc.

This is read-only: we GET the page and inspect the rendered form HTML.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ POST form(s) missing visible CSRF/nonce field | WordPress forms should use wp_nonce_field() to embed a `_wpnonce` input and check it server-side with wp_verify_nonce() or check_admin_referer(). REST endpoints should require X-WP-Nonce header. |
| info | All ⟨seen_forms⟩ POST form(s) have visible CSRF/nonce inputs | No action needed for this check. |
| info | No POST forms found to audit for CSRF tokens | No action needed. |

## Evidence the check records

- No POST forms found to audit for CSRF tokens: Probed ⟨count⟩ pages; no `<form method=post>` HTML found.
- ⟨count⟩ POST form(s) missing visible CSRF/nonce field: POST forms with no `_wpnonce` / `_token` / `csrfmiddlewaretoken` / `nonce` input: ⟨lines⟩ Note: this is heuristic — some plugins put the nonce in a header set by JS, which we can't see. Manually verify each form post in browser DevTools.
- All ⟨seen_forms⟩ POST form(s) have visible CSRF/nonce inputs: Found nonce/token fields in every form across ⟨count⟩ probed pages.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: SI-10
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.h
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.25

## References

- primary: https://owasp.org/www-community/attacks/csrf
- deep dive: https://portswigger.net/web-security/csrf

## Run only this check

```
wpsecscan only csrf_nonce https://example.com
```

`only` runs this check alone and prints its findings.
