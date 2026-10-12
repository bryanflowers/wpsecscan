---
id: wp_rest_methods
title: "REST method enumeration"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 92
---

# REST method enumeration

**check_id**: `wp_rest_methods`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WP REST API method enumeration via OPTIONS.

For each REST namespace discovered by rest_api, send OPTIONS and look at the
Allow header. Plugins that register POST/PUT/DELETE endpoints sometimes forget
to gate them behind capability checks.

## Request footprint

The module contains 1 request call(s) to the target (REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | REST ⟨value⟩ allows write methods: ⟨value⟩ | Audit the plugin's REST registration. Every write method should have `'permission_callback' => function($req){ return current_user_can('...'); }` set. |
| info | No REST namespaces advertise write methods unauthenticated | No action needed. |

## Evidence the check records

- No REST namespaces advertise write methods unauthenticated: OPTIONS sent to ⟨count⟩ known REST paths; none returned write-method Allow headers.
- REST ⟨value⟩ allows write methods: ⟨value⟩: OPTIONS ⟨value⟩ -&gt; 200 with `Allow: ⟨value⟩`. OPTIONS reflects every method the plugin registered, regardless of authn requirement. Verify each write method actually rejects anonymous clients by sending one POST/PUT/DELETE.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# Enumerate writable REST namespaces:
for ns in wp/v2/posts wp/v2/users wp/v2/comments wp/v2/media contact-form-7/v1 wc/v3; do echo "--- $ns"; curl -sX OPTIONS https://example.com/wp-json/$ns -i | grep -iE 'allow:|access-control'; done
# Lock down via rest_endpoints filter or rest_authentication_errors in functions.php
# WooCommerce: regenerate API keys at WooCommerce → Settings → Advanced → REST API
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only wp_rest_methods https://example.com
```

`only` runs this check alone and prints its findings.
