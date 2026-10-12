---
id: wc_api_key_escalation
title: "WooCommerce REST key scope advisory (A28)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 142
---

# WooCommerce REST key scope advisory (A28)

**check_id**: `wc_api_key_escalation`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: low
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-269
**D3FEND**: D3-CRO

## What it does

A28 (v2.6.0) — WooCommerce REST API key scope-escalation audit.

WooCommerce REST API keys (consumer_key + consumer_secret) come in 3
scopes: read, write, read_write. When a key with `read_write` scope is
used, several historical bugs let the same Basic Auth hit non-WC
endpoints — including `/wp-json/wp/v2/users/me/application-passwords/
introspect` which leaks the user's app-password fingerprints.

Passive: probe `/wp-json/wp/v2/users/me/application-passwords` with
NO auth + check the WWW-Authenticate header for "application password"
hint. The presence of that hint, combined with the existence of
`/wp-json/wc/v3/system_status`, suggests WC and WP-API live on the
same auth surface — the operator should audit their API-key scope.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | WP REST + WooCommerce REST both present — verify API-key scope is read-only | 1. Audit WooCommerce → Settings → Advanced → REST API → Keys. 2. Every integration key should be `read` scope unless write is genuinely required. 3. Move write-scope integrations to Application Passwords with capability-restricted users instead. 4. Rotate any key whose scope you can't justify. |

## Evidence the check records

- WP REST + WooCommerce REST both present — verify API-key scope is read-only: Both `/wp-json/wp/v2/users/me/application-passwords` and `/wp-json/wc/v3/system_status` are reachable on this install. WC API keys with `read_write` scope have historically been usable against non-WC WP REST endpoints when Basic Auth is accepted at both layers.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-6
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only wc_api_key_escalation https://example.com
```

`only` runs this check alone and prints its findings.
