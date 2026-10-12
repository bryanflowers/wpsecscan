---
id: db_admin_login_probe
title: "Adminer/phpMyAdmin login-form depth probe"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 102
---

# Adminer/phpMyAdmin login-form depth probe

**check_id**: `db_admin_login_probe`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

Deep probe for exposed Adminer / phpMyAdmin login pages.

The existing exposed_files check flags `/adminer.php` and `/phpmyadmin/`
on 200/403 status. This check goes deeper: when a 200 response is
returned, parse the body for the actual Adminer/phpMyAdmin login form,
which means the tool is fully reachable from the public internet (not
just behind a static-file rewrite).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Public ⟨tool⟩ login form reachable at ⟨path⟩ | 1. Delete ⟨tool⟩ from the web root immediately if it's not in active use. It's not part of WordPress; it was probably installed ad-hoc during a migration or troubleshooting session. 2. If you need ⟨tool⟩, restrict access to specific IPs at the web server (nginx `allow X; deny all;`) or move it behind HTTP basic auth. 3. Verify the DB user ⟨tool⟩ connects as is limited to the WP database — not a global root account. |

## Evidence the check records

- Public ⟨tool⟩ login form reachable at ⟨path⟩: GET ⟨path⟩ → HTTP 200 with ⟨tool⟩ login form in the response body. This is a fully-functional database-administration tool reachable from the public internet. An attacker only needs valid DB credentials (or a credential-stuffing match) to log in.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only db_admin_login_probe https://example.com
```

`only` runs this check alone and prints its findings.
