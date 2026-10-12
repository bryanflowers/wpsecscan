---
id: multisite_sso_key_reuse
title: "WP Multisite SSO key reuse audit (A13)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 132
---

# WP Multisite SSO key reuse audit (A13)

**check_id**: `multisite_sso_key_reuse`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-321
**D3FEND**: D3-CRO

## What it does

A13 (v2.6.0) — WordPress Multisite SSO HMAC key reuse.

WP Multisite networks that ship a custom SSO between sub-sites often
reuse a single SECRET_AUTH_KEY across the network. When that key
leaks (via wp-config.php exposure, backup file, GitHub repo), an
attacker can forge auth cookies for ANY sub-site.

Probe approach: identify multisite via the standard fingerprints (the
existing `multisite` check covers this); cross-check whether the
sub-site cookies share the same `Path=/` scope (a per-site cookie
restricted to its sub-path is much safer).

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WP Multisite cookies scoped to / (network-wide) — verify SSO key isolation | 1. Audit wp-config.php — confirm SECRET_AUTH_KEY etc. are SET (not the default placeholders) and rotated quarterly. 2. If sub-sites have very different trust levels, use the COOKIE_DOMAIN constant to scope cookies per-subsite. 3. Rotate SECRET_* keys NOW if wp-config.php has ever been committed to a public repo or backed up to a public bucket. |

## Evidence the check records

- WP Multisite cookies scoped to / (network-wide) — verify SSO key isolation: Login Set-Cookie headers use Path=/ — every sub-site shares the cookie scope. If SECRET_AUTH_KEY / SECRET_NONCE_KEY etc. in wp-config.php are SHARED across the network, a leak of one sub-site's cookies validates against any other. Sample Set-Cookie headers: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 3.6.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only multisite_sso_key_reuse https://example.com
```

`only` runs this check alone and prints its findings.
