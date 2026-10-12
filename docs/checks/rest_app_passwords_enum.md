---
id: rest_app_passwords_enum
title: "REST Application Passwords auth probe (#62)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 84
---

# REST Application Passwords auth probe (#62)

**check_id**: `rest_app_passwords_enum`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-287
**D3FEND**: D3-MFA

## What it does

WP REST application-passwords enumeration probe.

Round-64 #62 — WordPress 5.6+ supports Application Passwords. The REST
route `/wp/v2/users/me/application-passwords` lists active app-passwords
for the authenticated user; if exposed without auth (misconfigured
permission_callback in a plugin that re-registers the route), an
attacker gets the password names + UUIDs (not the secret) which is
already enough to fingerprint third-party integrations.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Application Passwords endpoint reachable unauthenticated: ⟨path⟩ | WP-core requires authentication for this endpoint. A 200 indicates a plugin has registered a permission_callback returning true. Audit your plugins for re-registration of /users/me/application-passwords. Specifically check any plugin that customises REST permissions. Application Passwords can be disabled site-wide if unused: add_filter('wp_is_application_passwords_available', '__return_false'); |
| info | Application Passwords endpoint properly requires auth | No action needed. Ensure Application Passwords are rotated if any 3rd-party integration is decommissioned. |

## Evidence the check records

- Application Passwords endpoint reachable unauthenticated: ⟨path⟩: GET ⟨path⟩ -&gt; 200 Body (first 200 chars): ⟨body⟩
- Application Passwords endpoint properly requires auth: GET ⟨path⟩ -&gt; 401 (expected)

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only rest_app_passwords_enum https://example.com
```

`only` runs this check alone and prints its findings.
