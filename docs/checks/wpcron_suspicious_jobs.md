---
id: wpcron_suspicious_jobs
title: "Suspicious wp-cron callbacks (companion) (#64)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 90
---

# Suspicious wp-cron callbacks (companion) (#64)

**check_id**: `wpcron_suspicious_jobs`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: critical
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1053.003 — Cron
**CWE**: CWE-506
**D3FEND**: D3-FCR

## What it does

wp-cron audit — flag suspicious scheduled callbacks (companion-assisted).

Round-64 #64 — webshells commonly install themselves as a wp-cron job
to maintain persistence even if the original entry-point file is
removed. The companion plugin exposes
/wp-json/wpsecscan-companion/v1/cron-jobs which returns the active
scheduled hooks + their callbacks. We flag callbacks that match
known-bad patterns (eval, base64_decode, system, shell_exec, file_get_
contents from remote URLs, etc.).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Suspicious wp-cron job: ⟨value⟩ | This wp-cron job is likely persistence for a webshell. Steps: 1. From wp-cli: `wp cron event delete <hook-name>` 2. Find + remove the PHP file registering the hook (grep 'wp_schedule_event' your code). 3. Audit other persistence (DB triggers, mu-plugins, .htaccess auto_prepend_file). 4. Rotate admin credentials + WP salts. 5. Restore from a known-clean backup if compromise is confirmed. |
| info | ⟨count⟩ wp-cron jobs scheduled — none matched malicious patterns | If site is on a host without real cron, switch DISABLE_WP_CRON=true + system cron for reliability. |

## Evidence the check records

- Suspicious wp-cron job: ⟨value⟩: Hook: ⟨value⟩ Callback: ⟨value⟩ Matched: ⟨value⟩ Next run: ⟨value⟩
- ⟨count⟩ wp-cron jobs scheduled — none matched malicious patterns: Checked ⟨count⟩ hook(s); review periodically.

## Compliance mapping

- **compliance_map / pci_dss**: 10.2.1
- **compliance_map / nist_800_53**: AU-2
- **compliance_map / iso_27001**: A.8.16

## Run only this check

```
wpsecscan only wpcron_suspicious_jobs https://example.com
```

`only` runs this check alone and prints its findings.
