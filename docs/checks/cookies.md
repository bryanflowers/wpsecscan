---
id: cookies
title: "Cookie hardening"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 67
---

# Cookie hardening

**check_id**: `cookies`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1539 — Steal Web Session Cookie

## What it does

Cookie hardening check — inspect Set-Cookie flags on common WP endpoints.

Looks specifically at /wp-login.php and /wp-admin/ (which set wp-* cookies on
login attempts) for missing Secure / HttpOnly / SameSite flags.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | ⟨count⟩ cookie(s) missing security flags | Set Secure (HTTPS-only), HttpOnly (no JS access), and SameSite=Lax/Strict (CSRF mitigation). For WP cookies, in wp-config.php: define('COOKIE_DOMAIN', 'example.com'); define('FORCE_SSL_ADMIN', true); At the server level (Nginx) you can also rewrite Set-Cookie headers. |
| info | All observed cookies have appropriate security flags | No action needed. |
| info | No cookies observed from probed endpoints | No action needed. |

## Evidence the check records

- No cookies observed from probed endpoints: GET /wp-login.php, /wp-admin/, and / returned no Set-Cookie headers.
- All observed cookies have appropriate security flags: Inspected ⟨count⟩ cookie(s); none missing required flags.

## Suggested fix

Force secure WP cookies. Where to apply it: wp-config.php.

```php
define('FORCE_SSL_ADMIN', true);
@ini_set('session.cookie_secure', 1);
@ini_set('session.cookie_httponly', 1);
@ini_set('session.cookie_samesite', 'Lax');
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/wp-login.php | grep -i set-cookie
curl -sI https://example.com/wp-admin/ | grep -i set-cookie
```

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-23
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(a)(2)(i)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.4
- **compliance_v2 / iso_27001_2022**: A.8.5

## Run only this check

```
wpsecscan only cookies https://example.com
```

`only` runs this check alone and prints its findings.
