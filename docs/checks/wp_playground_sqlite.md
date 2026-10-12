---
id: wp_playground_sqlite
title: "WP Playground / SQLite database file exposure (A4)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Injection & client-side"
words: 220
---

# WP Playground / SQLite database file exposure (A4)

**check_id**: `wp_playground_sqlite`
**aggressive**: no
**category**: Injection & client-side
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1005 — Data from Local System
**CWE**: CWE-540
**D3FEND**: D3-FA

## What it does

A4 (v2.6.0) — WP Playground / SQLite-Database-Integration detection.

The official "wp-now" / "WordPress Playground" runtime ships a SQLite
database driver instead of MySQL. The same SQLite-Database-Integration
plugin is used in production by anyone running WordPress on a host
without MySQL.

The plugin has its own CVE family — particularly around the SQL
translation layer that converts MySQL queries to SQLite. Some
historical bugs:

  • Translation-layer query injection (CVE-2024-3xxx).
  • Database file (`wp-content/database/.ht.sqlite`) reachable via the
    web when .htaccess isn't honoured (nginx-served installs).
  • Backup file (`.ht.sqlite.bak`) sometimes left readable.

This check fingerprints the plugin via the rendered HTML + probes the
canonical database-file paths.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WordPress SQLite database file is web-reachable: ⟨path⟩ | 1. IMMEDIATE: block /wp-content/database/ at the WAF. 2. Move the database file outside the web root (set DB_DIR in wp-config.php to a path above ABSPATH). 3. On nginx, add `location /wp-content/database/ { deny all; }`. 4. Rotate all user passwords + any API keys stored in wp_options. 5. Audit for unauthorised access via web-server logs. 6. After remediation, change wp-config.php SECRET_AUTH_KEY etc. so any session tokens captured during the leak window become invalid. |
| high | Possible SQLite database file reachable: ⟨path⟩ | Block /wp-content/database/ at the WAF and move the DB file outside the web root (see DB_DIR in wp-config.php). |
| info | WordPress SQLite-Database-Integration detected (DB file not web-reachable) | Verify wp-config.php has DB_DIR set to a path above ABSPATH, and that .htaccess or nginx config denies /wp-content/database/. |

## Evidence the check records

- WordPress SQLite-Database-Integration detected (DB file not web-reachable): Homepage HTML or response headers indicate this install uses the official SQLite-Database-Integration plugin (or wp-now / WordPress Playground). The /wp-content/database/ path is NOT reachable from the web, which is the expected hardened state.
- WordPress SQLite database file is web-reachable: ⟨path⟩: GET ⟨path⟩ → HTTP 200 (⟨count⟩ bytes). First 32 bytes (hex): ⟨value⟩ Magic bytes confirm this is the live SQLite file. Anyone on the internet can download the entire WordPress database (users, options, posts, all metadata).
- Possible SQLite database file reachable: ⟨path⟩: GET ⟨path⟩ → HTTP 200 (⟨count⟩ bytes). Doesn't match the SQLite magic header, but the path is reachable and is the canonical SQLite-DB-Integration location.

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-28
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only wp_playground_sqlite https://example.com
```

`only` runs this check alone and prints its findings.
