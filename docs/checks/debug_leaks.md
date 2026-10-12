---
id: debug_leaks
title: "Debug & info leaks"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 161
---

# Debug & info leaks

**check_id**: `debug_leaks`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A09:2021 — Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.004 — Gather Victim Host Information: Client Configurations

## What it does

Debug and information-leak check.

Requests /wp-content/debug.log and reports it (high) when it is readable and
contains PHP or WordPress log text. Requests /?p[]=1 and reports (medium) when
the body carries PHP error markers: "Fatal error", "Stack trace:", "Uncaught
Error/Exception", or a full "Warning: ... in /path/file.php on line N" line.
Fetches / and reports (low) a wp-emoji-release.min.js?ver= URL, which reveals
the WordPress version. If nothing matches it emits one info finding. Fix: keep
WP_DEBUG_LOG outside the docroot, turn WP_DEBUG_DISPLAY and display_errors
off, and optionally remove the emoji script. Three GET requests in total.

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | /wp-content/debug.log is publicly readable | Block /wp-content/debug.log at the server, and set `define('WP_DEBUG_LOG', '/path/outside/docroot/debug.log');` so logs never live under the docroot. In production, also set `WP_DEBUG_DISPLAY` to false. |
| medium | PHP error / stack trace leaks via crafted query | In wp-config.php: set `WP_DEBUG_DISPLAY` to false and `display_errors` to Off in php.ini. Errors should go to a log file, never the response body. |
| low | wp-emoji-release.min.js exposes WP version via ?ver= (⟨value⟩) | Disable the emoji feature (it's rarely useful): `remove_action('wp_head','print_emoji_detection_script', 7);` and the related actions. Or strip ?ver= from all asset URLs via a filter. |
| info | No debug / info leaks detected | No action needed. |

## Evidence the check records

- No debug / info leaks detected: debug.log not readable, no stack traces from crafted query, no emoji version fingerprint.
- /wp-content/debug.log is publicly readable: GET /wp-content/debug.log → 200; first lines: ⟨preview⟩
- PHP error / stack trace leaks via crafted query: GET /?p[]=1 → response contains PHP error markers: ⟨preview⟩
- wp-emoji-release.min.js exposes WP version via ?ver= (⟨value⟩): Found `wp-emoji-release.min.js?ver=⟨value⟩` in homepage.

## Suggested fix

Move debug log outside docroot. Where to apply it: wp-config.php.

```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', '/path/outside/docroot/wp-debug.log');
define('WP_DEBUG_DISPLAY', false);
@ini_set('display_errors', 0);
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -sI https://example.com/wp-content/debug.log
curl -s https://example.com/?p\[\]=1 | head -20
```

## Compliance mapping

- **compliance_map / pci_dss**: 10.2.1
- **compliance_map / nist_800_53**: AU-3
- **compliance_map / iso_27001**: A.8.15
- **compliance_v2 / hitrust**: 10.g
- **compliance_v2 / cmmc**: SI.L1-3.14.1
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 4.1
- **compliance_v2 / iso_27001_2022**: A.8.9

## Run only this check

```
wpsecscan only debug_leaks https://example.com
```

`only` runs this check alone and prints its findings.
