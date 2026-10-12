---
id: plugin_install_rest_race
title: "REST plugin-install endpoint auth audit (A22)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 138
---

# REST plugin-install endpoint auth audit (A22)

**check_id**: `plugin_install_rest_race`
**aggressive**: no
**category**: Authentication & session
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-IAA

## What it does

A22 (v2.6.0) — POST /wp-json/wp/v2/plugins race / slug-validation probe.

WordPress core REST endpoint `POST /wp-json/wp/v2/plugins` accepts a
`slug` parameter and installs the matching plugin from the .org
repository. The slug is validated, but multiple CVEs in the 2024-2025
window allowed:

  • Bypass of the slug regex via URL-encoded path-traversal patterns.
  • Race condition where parallel POSTs with conflicting slugs let one
    install an arbitrary slug before validation completed.

The endpoint requires `install_plugins` capability — passive probe
just confirms auth IS enforced (we don't try the race, which would
actually install plugins).

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | REST plugin-install endpoint accepts unauthenticated POST | 1. IMMEDIATE: set define('DISALLOW_FILE_MODS', true); in wp-config.php to disable all plugin installs over HTTP. 2. Audit which plugin removed the permission callback (likely a custom plugin overrode rest_authentication_errors). 3. Re-install WordPress core after rotating SECRET_* keys. |
| info | REST plugin-install endpoint properly auth-gated | Endpoint is correctly gated. Confirm: - WordPress core &gt;= 6.5 (patched slug-regex bypass) - DISALLOW_FILE_MODS or FS_METHOD restrictions are in place in wp-config.php if installs should be admin-only-via-SSH. |

## Evidence the check records

- REST plugin-install endpoint properly auth-gated: POST /wp-json/wp/v2/plugins → HTTP ⟨status⟩ (auth required).
- REST plugin-install endpoint accepts unauthenticated POST: POST /wp-json/wp/v2/plugins {'slug':'...'} → HTTP ⟨status⟩. Body: ⟨value⟩ An attacker can install ANY plugin from the .org repo. Combined with a vulnerable plugin upload, this is RCE.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only plugin_install_rest_race https://example.com
```

`only` runs this check alone and prints its findings.
