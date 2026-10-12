---
id: wpconfig_hardening_audit
title: "wp-config hardening inferred from remote signals (#52)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 104
---

# wp-config hardening inferred from remote signals (#52)

**check_id**: `wpconfig_hardening_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-16
**D3FEND**: D3-NTA

## What it does

wp-config.php hardening inference from remote signals.

Round-64 #52 — wp-config.php sits on the server (we can't read it), but
several of its hardening flags show up in remote-observable telemetry.
This check flags the absence of: DISALLOW_FILE_EDIT, WP_DEBUG_DISPLAY=
false, DISALLOW_FILE_MODS, FORCE_SSL_ADMIN. Each is inferred from
indirect signals (admin theme editor reachable, PHP errors in body,
plugin upload form present, http:// login redirect).

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | wp-admin allows plain-HTTP login flow — FORCE_SSL_ADMIN missing | Add to wp-config.php: define('FORCE_SSL_ADMIN', true); Plus an HTTP-&gt;HTTPS 301 at the web-server level. |
| medium | PHP debug output leaks in HTTP body | Add to wp-config.php (production): define('WP_DEBUG', false); define('WP_DEBUG_DISPLAY', false); define('WP_DEBUG_LOG', true); // log instead of display Server-side: error_reporting(0); display_errors=Off in php.ini. |
| medium | Theme editor reachable — DISALLOW_FILE_EDIT not set | Add to wp-config.php: define('DISALLOW_FILE_EDIT', true); define('DISALLOW_FILE_MODS', true); Disables the admin file editor — a top-3 webshell-install path. |

## Evidence the check records

- PHP debug output leaks in HTTP body: Probe response contained: ⟨value⟩
- Theme editor reachable — DISALLOW_FILE_EDIT not set: GET /wp-admin/theme-editor.php -&gt; ⟨value⟩, no login redirect detected
- wp-admin allows plain-HTTP login flow — FORCE_SSL_ADMIN missing: GET /wp-admin/ -&gt; redirect to ⟨loc⟩

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only wpconfig_hardening_audit https://example.com
```

`only` runs this check alone and prints its findings.
