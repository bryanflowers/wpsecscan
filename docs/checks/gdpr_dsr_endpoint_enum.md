---
id: gdpr_dsr_endpoint_enum
title: "GDPR DSR ajax-action auth check (A21)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 106
---

# GDPR DSR ajax-action auth check (A21)

**check_id**: `gdpr_dsr_endpoint_enum`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-IAA

## What it does

A21 (v2.6.0) — GDPR DSR endpoint enumeration.

Core WordPress (since 4.9.6) ships data-export + data-erasure tools at
`/wp-admin/tools.php?page=export_personal_data` and `=remove_personal_data`.
The handler endpoints (`/wp-admin/admin-ajax.php?action=wp-privacy-*`)
are sometimes misconfigured by 3rd-party data-source plugins, leaving
the request-personal-data flow callable without authentication.

Passive: probe both the wp-admin pages + the ajax actions. A 200 on
the admin page without auth is a low-info advisory (login bypass would
need separate evidence); a 200 on the ajax action without nonce is a
medium.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | GDPR DSR ajax action callable without nonce: ⟨action⟩ | 1. Verify your privacy plugin (or a custom plugin handling '⟨action⟩') checks current_user_can('manage_options') and wp_verify_nonce() before doing any work. 2. Confirm WordPress core version is current — early WP 5.x ones had nonce-bypass bugs in this flow. |

## Evidence the check records

- GDPR DSR ajax action callable without nonce: ⟨action⟩: POST admin-ajax.php?action=⟨action⟩ → HTTP 200, body has no auth/nonce error: ⟨value⟩ An attacker could trigger / drain the DSR queue.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.34

## Run only this check

```
wpsecscan only gdpr_dsr_endpoint_enum https://example.com
```

`only` runs this check alone and prints its findings.
