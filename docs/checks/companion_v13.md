---
id: companion_v13
title: "Companion v1.3 endpoint consumers (B36-B47)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 191
---

# Companion v1.3 endpoint consumers (B36-B47)

**check_id**: `companion_v13`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-1392
**D3FEND**: D3-IAA

## What it does

B36-B47 (v2.6.0) — consumers of the companion plugin v1.3 endpoints.

Like `companion_advanced`, each consumer no-ops when --companion-token
isn't set so the scan doesn't add noise.

  B36 /users-with-app-passwords  — stale AP / many-AP / no-last-used flags
  B37 /recent-uploads            — recent PHP/JS in uploads = high (web-shell)
  B39 /wp-cron-event-history     — event count = derived (no logger active)
  B42 /admin-notice-content      — surface as info; manual review for ads
  B47 /site-health-tests         — flag each critical-status WP test

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | PHP/JS files in uploads/ (web-shell indicator): ⟨count⟩ | 1. Audit each file: PHP in uploads/ is almost always a web-shell. 2. Block .php execution under uploads/ via web-server config (Apache: `<FilesMatch \.ph(p[0-9]?\|tml)$> Require all denied`; nginx: `location ~ ^/wp-content/uploads/.*\.ph(p[0-9]?\|tml)$ { deny all; }`). 3. Rotate all admin passwords + audit recent admin activity. |
| high | WordPress Site Health CRITICAL: ⟨value⟩ | Open /wp-admin/site-health.php for the full Site Health explanation + recommended fix. Critical-status tests are the WP core team's curated 'must-fix' set. |
| medium | App Password stale (&gt;180d): ⟨value⟩ / ⟨value⟩ | Revoke or rotate via /wp-admin/profile.php → Application Passwords. |
| low | Many admin-notice-related wp_options (⟨value⟩) — review for adware | Audit wp_options rows whose option_name contains 'admin_notice' or 'dismissed'. Each should belong to a known-installed plugin; orphans suggest a deactivated-but-not-cleaned plugin (or worse, a payload from a removed compromise). |
| low | WordPress Site Health recommended: ⟨value⟩ | Open /wp-admin/site-health.php for context. |
| info | WP-cron event history derived (no transient logger active) | Add to your theme's functions.php: add_action('init', function () { add_filter('wpsecscan_companion_cron_history', '__return_true'); }); Then re-scan to populate the history. |

## Evidence the check records

- WP-cron event history derived (no transient logger active): Companion returned ⟨value⟩ events derived from _get_cron_array(). For better drift detection, enable the wpsecscan_companion_cron_history filter so the plugin logs actual elapsed-time per run.
- Many admin-notice-related wp_options (⟨value⟩) — review for adware: ⟨value⟩ wp_options rows match admin_notice/dismissed. Some compromised plugins post admin notices with adware links. Review the first few entries: ⟨value⟩
- PHP/JS files in uploads/ (web-shell indicator): ⟨count⟩: Recent PHP/JS uploads detected: ⟨value⟩ ...
- WordPress Site Health CRITICAL: ⟨value⟩: Test name: ⟨value⟩ Label: ⟨value⟩ Badge: ⟨value⟩
- App Password stale (&gt;180d): ⟨value⟩ / ⟨value⟩: Created: ⟨value⟩ (⟨age⟩d ago) Last used: ⟨value⟩ (⟨last⟩d ago) Last IP: ⟨value⟩
- WordPress Site Health recommended: ⟨value⟩: Test: ⟨value⟩, badge: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.7
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.16

## Run only this check

```
wpsecscan only companion_v13 https://example.com
```

`only` runs this check alone and prints its findings.
