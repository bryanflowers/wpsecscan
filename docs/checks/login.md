---
id: login
title: "Login surface"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 150
---

# Login surface

**check_id**: `login`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.001 — Brute Force: Password Guessing

## What it does

Login-surface check.

Makes three requests. GET /wp-login.php is reported (info) when the response
is 200 and contains the login form. GET /wp-admin/ without following
redirects is reported (info) on 200, 301 or 302. POST /xmlrpc.php sending
system.listMethods is reported when a valid methodResponse comes back: medium
if system.multicall or wp.getUsersBlogs is listed, otherwise low. If none of
the three respond, one info finding says the surface looks hardened. Fix:
restrict /wp-login.php and /wp-admin/ by IP or 2FA, and disable or block
XML-RPC if Jetpack and the mobile app are not in use.

## Request footprint

The module contains 3 request call(s) to the target (GET x2, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | XML-RPC endpoint is enabled | If you don't use Jetpack or the WP mobile app, disable XML-RPC. Block /xmlrpc.php at the server (Nginx: `location = /xmlrpc.php { deny all; }`). If you need it, restrict by IP and disable system.multicall via the `xmlrpc_methods` filter to neutralize the brute-force amplifier. |
| info | /wp-admin/ reachable | Same as wp-login.php — restrict by IP/2FA or rename the admin path. |
| info | Default login page /wp-login.php is reachable | Consider moving the admin URL with a plugin (e.g. WPS Hide Login) and add IP allow-listing or 2FA. The default path is the #1 brute-force target. |
| info | Login surface appears hardened | No action needed. |

## Evidence the check records

- Default login page /wp-login.php is reachable: GET /wp-login.php → 200, looks like the WP login form.
- /wp-admin/ reachable: GET /wp-admin/ → ⟨value⟩
- XML-RPC endpoint is enabled: POST /xmlrpc.php system.listMethods → 200 with valid methodResponse. ⟨value⟩
- Login surface appears hardened: /wp-login.php and /wp-admin/ not reachable as default; XML-RPC not responding.

## Suggested fix

Disable XML-RPC + system.multicall amplifier. Where to apply it: functions.php.

```php
add_filter('xmlrpc_enabled', '__return_false');
add_filter('xmlrpc_methods', function($m){ unset($m['system.multicall']); return $m; });
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/wp-login.php
curl -s -X POST https://example.com/xmlrpc.php -H 'Content-Type: text/xml' --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
```

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.1
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(d)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: IA-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L1-3.5.1
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.1
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan only login https://example.com
```

`only` runs this check alone and prints its findings.
