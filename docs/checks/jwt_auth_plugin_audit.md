---
id: jwt_auth_plugin_audit
title: "JWT-Auth plugin secret-key audit (A17)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 146
---

# JWT-Auth plugin secret-key audit (A17)

**check_id**: `jwt_auth_plugin_audit`
**aggressive**: no
**category**: Authentication & session
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1606 — Forge Web Credentials
**CWE**: CWE-347
**D3FEND**: D3-CRO

## What it does

A17 (v2.6.0) — `jwt-authentication-for-wp-rest-api` plugin audit.

The popular Tmeister/Useful Team `jwt-authentication-for-wp-rest-api`
plugin had multiple CVEs around the JWT secret being:

  • Read from a constant (`define('JWT_AUTH_SECRET_KEY', '...')`) that
    devs frequently leave as the placeholder string or commit to repos.
  • Accepted from a query parameter in older versions.
  • Reusable across token-revocation events.

Passive: probe the plugin's canonical token endpoint
(`/wp-json/jwt-auth/v1/token`) and look for the secret-not-set error
message ("JWT is not configurated properly, please contact the
admin"), which means anyone can craft an unsigned token that the
plugin will accept.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | JWT-Auth plugin reports SECRET_KEY missing — anyone can forge admin tokens | 1. IMMEDIATE: deactivate the plugin until the secret is set. 2. In wp-config.php, add a strong random secret: define('JWT_AUTH_SECRET_KEY', '&lt;64-char-random&gt;'); 3. Generate via: `openssl rand -base64 48`. 4. Reactivate. Audit recent admin actions for forged tokens. |
| info | JWT-Auth plugin present + secret configured (probe rejected as expected) | Plugin is correctly configured. Rotate JWT_AUTH_SECRET_KEY every 90 days; revoke all issued tokens on rotation. |

## Evidence the check records

- JWT-Auth plugin reports SECRET_KEY missing — anyone can forge admin tokens: POST ⟨_ENDPOINT⟩ → HTTP ⟨value⟩ Body: ⟨value⟩ The plugin's secret key isn't configured; it falls back to a default-empty secret and accepts any HS256-signed token.
- JWT-Auth plugin present + secret configured (probe rejected as expected): POST ⟨_ENDPOINT⟩ → HTTP ⟨value⟩; plugin is hardened.

## Compliance mapping

- **compliance_map / pci_dss**: 3.6.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only jwt_auth_plugin_audit https://example.com
```

`only` runs this check alone and prints its findings.
