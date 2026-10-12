---
id: heartbeat_frontend
title: "Heartbeat API on front-end"
severity_max: low
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 128
---

# Heartbeat API on front-end

**check_id**: `heartbeat_frontend`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1499 — Endpoint DoS

## What it does

WordPress Heartbeat API frontend detection.

The Heartbeat API (`/wp-admin/admin-ajax.php?action=heartbeat`) polls every
15 seconds by default. It's needed in `/wp-admin` (post autosave, lock
detection) but rarely on the front-end of the public site, where it just
adds a persistent AJAX load on every visitor. This check looks for
`wp-heartbeat` references in the public homepage HTML and flags it as
low-severity perf/load advice with a one-line `wp_deregister_script` fix.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Heartbeat API loaded on the public front-end (every visitor polls every 15 s) | Disable Heartbeat on the front-end. Either install the 'Heartbeat Control' plugin and disable on the front-end only, or in your theme's functions.php: add_action('init', function() { if (!is_admin()) wp_deregister_script('heartbeat'); }, 1); Keep Heartbeat enabled in wp-admin so editors don't lose autosave. |
| info | Heartbeat API not loaded on front-end (good) | No action. |

## Evidence the check records

- Heartbeat API loaded on the public front-end (every visitor polls every 15 s): `wp-heartbeat` is referenced in homepage HTML. Every visitor's browser polls /wp-admin/admin-ajax.php every 15 s for the duration of their session, adding persistent server load + bandwidth without a clear use on the front-end.
- Heartbeat API not loaded on front-end (good): No `wp-heartbeat` script reference in homepage HTML.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 09.k
- **compliance_v2 / cmmc**: SC.L2-3.13.4
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 12.1
- **compliance_v2 / iso_27001_2022**: A.8.6

## Run only this check

```
wpsecscan only heartbeat_frontend https://example.com
```

`only` runs this check alone and prints its findings.
