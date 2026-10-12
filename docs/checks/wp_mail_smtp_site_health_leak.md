---
id: wp_mail_smtp_site_health_leak
title: "Site-Health debug dump SMTP-key leak (A26)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 104
---

# Site-Health debug dump SMTP-key leak (A26)

**check_id**: `wp_mail_smtp_site_health_leak`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-200
**D3FEND**: D3-CRO

## What it does

A26 (v2.6.0) — WP Mail SMTP key leak via Site Health debug dump.

Newer WP cores (6.5+) include Site Health debug info that can leak the
SMTP password unmasked when the WP Mail SMTP plugin is misconfigured.
The endpoint `/wp-admin/site-health.php?tab=debug` requires auth, but
some themes/plugins ship a public version (e.g. health-check helper
plugin's debug-info endpoint).

Passive: probe a few canonical site-health debug endpoints + flag
medium when they're reachable without auth.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Site Health debug dump reachable unauthenticated: ⟨path⟩ | 1. Block ⟨path⟩ at the WAF until verified. 2. Confirm WP Mail SMTP plugin is current (mask-password bug was fixed in 4.4.x). 3. ROTATE the SMTP password immediately. |

## Evidence the check records

- Site Health debug dump reachable unauthenticated: ⟨path⟩: GET ⟨path⟩ → HTTP 200 Debug dumps typically include SMTP host/port/user (and on buggy WP Mail SMTP versions, the password in cleartext). Body excerpt: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only wp_mail_smtp_site_health_leak https://example.com
```

`only` runs this check alone and prints its findings.
