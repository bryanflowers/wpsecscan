---
id: companion_v14
title: "Companion v1.4 endpoint consumers (B38-B45)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 162
---

# Companion v1.4 endpoint consumers (B38-B45)

**check_id**: `companion_v14`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-1392
**D3FEND**: D3-IAA

## What it does

B38-B45 (v2.7.0) — consumers of the companion plugin v1.4 endpoints.

No-op silently when --companion-token isn't set.

  B38 /plugin-license-keys     — confirm legitimate plugin licensing
  B40 /active-network-requests — outbound-traffic anomalies
  B41 /page-cache-info         — cache plugin + logged-in caching leak
  B43 /database-encoding       — non-utf8mb4 tables (homograph SQLi)
  B44 /customizer-bookmarks    — XSS in theme_mod values
  B45 /widget-block-html       — XSS in block widgets

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Customizer modifier contains script/iframe payload: ⟨value⟩ | 1. Open Appearance → Customize and remove the offending value (or replace it with a clean one). 2. If the value wasn't set by an admin, treat as a compromise — audit recent wp-admin activity. 3. Add the relevant theme_mod_* filter to escape any future user-supplied value before rendering. |
| high | Widget contains raw script/iframe: ⟨value⟩ | Open /wp-admin/widgets.php and remove the offending widget, or replace its HTML with a sanitized version. If this widget wasn't placed by an admin, treat as compromise. |
| medium | DB tables not using utf8mb4: ⟨value⟩ | Mixed charset/collation across tables enables emoji-homograph SQLi (single byte collation accepts a multibyte injection that later compares-equal). Convert each table to utf8mb4 with: ALTER TABLE wp_xxx CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci; Run wpsecscan/wpsecscan-companion's DB convert helper for safety. |
| medium | Outbound wp_remote_* traffic high: ⟨n⟩ requests in 24h | 1. Audit the top-hosts list — anything unfamiliar is suspect. 2. Block unknown outbound hosts at the firewall. 3. Audit recently-installed plugins; the outbound traffic originates from a plugin's wp_remote_* calls. |
| low | Plugins with empty license-key options: ⟨count⟩ | Either deactivate the plugin or enter a valid license. Unlicensed-plugin behaviour can include skipped security updates. |
| info | Page-cache plugin(s) active: ⟨value⟩ | Confirm logged-in users are NOT served from the page cache (privacy leak: another user can see the previous user's personalised page). Audit the cache plugin's 'cache-for-logged-in-users' setting (should be OFF). |

## Evidence the check records

- DB tables not using utf8mb4: ⟨value⟩: Connection charset: ⟨value⟩ Non-utf8mb4 tables (⟨count⟩): ⟨value⟩
- Plugins with empty license-key options: ⟨count⟩: Plugin license-key options exist but are empty: ⟨value⟩
- Outbound wp_remote_* traffic high: ⟨n⟩ requests in 24h: Last-24h outbound HTTP requests from wp_remote_*: ⟨n⟩. Top hosts: ⟨value⟩ High outbound volume is often a compromise indicator (crypto-miner / spam-mailer / data exfil).
- Page-cache plugin(s) active: ⟨value⟩: Detected: ⟨value⟩ Cache dir: ⟨value⟩ Cache size: ⟨size_gb⟩ GiB (⟨value⟩ files)
- Customizer modifier contains script/iframe payload: ⟨value⟩: Theme: ⟨value⟩ theme_mod key: ⟨value⟩ Value (truncated): ⟨value⟩
- Widget contains raw script/iframe: ⟨value⟩: wp_options.option_name: ⟨value⟩ Value (truncated): ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 10.2.1
- **compliance_map / nist_800_53**: AU-2
- **compliance_map / iso_27001**: A.8.15

## Run only this check

```
wpsecscan only companion_v14 https://example.com
```

`only` runs this check alone and prints its findings.
