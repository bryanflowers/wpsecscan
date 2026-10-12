---
id: app_passwords
title: "Application Passwords audit"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 222
---

# Application Passwords audit

**check_id**: `app_passwords`
**aggressive**: no
**category**: Authentication & session
**max severity**: low
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

WordPress Application Passwords audit.

Since WP 5.6, Application Passwords are a built-in way for clients to
authenticate to the REST API without using the user password. They're great
for legitimate integrations and a constant target for attackers because:
  - The endpoint /wp-json/wp/v2/users/me?context=edit returns 401 with a
    WWW-Authenticate header that reveals whether Application Passwords are on.
  - The /wp-admin/profile.php?page=application-passwords surface is the
    creation flow.

This check looks for:
  - Whether the Application Passwords feature is enabled (info)
  - Whether the authorization endpoint at /wp-admin/authorize-application.php
    is reachable (info)
  - Whether the JWT alternative plugin is installed

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Application Password authorize endpoint is reachable | Restrict the endpoint to a known set of IPs or behind an auth gate if not actively used. Educate admins to NEVER click 'Authorize' links they didn't initiate themselves. |
| info | Application Passwords / JWT auth not detected | No action needed. |
| info | JWT Authentication for WP REST API plugin is installed | Make sure the JWT-Auth plugin is on its latest release (≥1.3.7). Confirm JWT_AUTH_SECRET_KEY is set to a strong random value in wp-config.php. |
| info | WordPress Application Passwords feature is enabled | If you don't integrate any external services with WordPress, disable Application Passwords: add_filter('wp_is_application_passwords_available', '__return_false'); If you do use them, audit /wp-admin/profile.php under each admin's profile for unrecognized entries. |

## Evidence the check records

- Application Password authorize endpoint is reachable: GET /wp-admin/authorize-application.php -&gt; ⟨value⟩ This is the OAuth-style consent screen for issuing Application Passwords. An attacker with a phishing pretext can social-engineer an admin into authorizing a malicious client.
- JWT Authentication for WP REST API plugin is installed: GET /wp-json/jwt-auth/v1/token -&gt; HTTP ⟨value⟩ The 'JWT Authentication for WP REST API' plugin is in active use. Several historical CVEs (e.g. CVE-2024-1631) — keep it updated.
- Application Passwords / JWT auth not detected: No matching WWW-Authenticate header, /wp-admin/authorize-application.php returned non-2xx, no jwt-auth namespace.
- WordPress Application Passwords feature is enabled: GET /wp-json/wp/v2/users/me with a fake Basic auth -&gt; HTTP ⟨value⟩ WWW-Authenticate: ⟨value⟩ Application Passwords are how the REST API authenticates non-cookie clients (5.6+). Built-in feature; on by default unless explicitly disabled.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.6
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan only app_passwords https://example.com
```

`only` runs this check alone and prints its findings.
