---
id: wp_debug_display_via_rest
title: "WP_DEBUG_DISPLAY via malformed REST POST"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 133
---

# WP_DEBUG_DISPLAY via malformed REST POST

**check_id**: `wp_debug_display_via_rest`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.004 — Gather Victim Host: Client Configurations

## What it does

Detect WP_DEBUG_DISPLAY=true via deliberately malformed REST request.

POST malformed JSON to /wp-json/wp/v2/posts (no auth). A correctly-
configured server returns a clean JSON error. A misconfigured server
(WP_DEBUG_DISPLAY=true in production) leaks the PHP stack trace, file
paths, and framework versions in the 4xx/5xx response body.

Distinct from `debug_leaks.py` which probes /?p[]=1 — this hits the
REST router specifically, which uses different error machinery.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WP_DEBUG_DISPLAY=true leaks PHP error via REST API malformed-body response | In wp-config.php: define('WP_DEBUG', false); // or true with the next two off define('WP_DEBUG_DISPLAY', false); define('WP_DEBUG_LOG', true); // log to file instead In php.ini (and any per-vhost override): display_errors = Off log_errors = On Then verify by re-running this check or POSTing the same broken JSON manually. |

## Evidence the check records

- WP_DEBUG_DISPLAY=true leaks PHP error via REST API malformed-body response: POST /wp-json/wp/v2/posts with invalid JSON → HTTP ⟨value⟩ with a PHP error/stack-trace shape in the body: ⟨value⟩ This indicates `define('WP_DEBUG_DISPLAY', true)` in wp-config.php (or `display_errors = On` in php.ini) for the production environment. PHP error output should never appear in HTTP responses on a public site — it leaks absolute filesystem paths, framework versions, and the specific PHP version in use.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-11
- **compliance_map / iso_27001**: A.8.27
- **compliance_v2 / hitrust**: 10.a
- **compliance_v2 / cmmc**: SI.L2-3.14.6
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 4.8
- **compliance_v2 / iso_27001_2022**: A.8.27

## Run only this check

```
wpsecscan only wp_debug_display_via_rest https://example.com
```

`only` runs this check alone and prints its findings.
