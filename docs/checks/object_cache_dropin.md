---
id: object_cache_dropin
title: "/wp-content/object-cache.php drop-in audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 173
---

# /wp-content/object-cache.php drop-in audit

**check_id**: `object_cache_dropin`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Gather Victim Host: Software

## What it does

Detect /wp-content/object-cache.php drop-in and fingerprint the plugin.

WordPress drop-ins live in /wp-content/ and are loaded before any plugin
or theme. They're not listed in /wp/v2/plugins, so plugin-enumeration
misses them entirely. The most common drop-in is `object-cache.php`,
installed by Redis Object Cache, W3 Total Cache, LiteSpeed Cache,
WP Redis, etc. Each has had CVEs.

We probe the file existence (200 with text/plain or text/x-php is the
common signal), read the first 2 KB to fingerprint the installer, and
emit a finding the user can cross-reference against the CVE DB.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | /wp-content/object-cache.php drop-in source publicly readable (⟨vendor⟩) | 1. Cross-reference the identified vendor against the CVE database — `wpsecscan` flags known CVEs separately, but ⟨vendor⟩ drop-ins specifically have had auth-bypass and cache-poisoning issues. 2. Investigate why .php is being served as text. Likely: PHP-FPM handler missing or `AddType application/x-httpd-php` not applied to /wp-content/. Test with `curl -I` against any other .php file under /wp-content/ to scope the misconfig. 3. If the drop-in isn't actively in use, delete it. Drop-ins persist after the parent plugin is removed. |

## Evidence the check records

- /wp-content/object-cache.php drop-in source publicly readable (⟨vendor⟩): GET /wp-content/object-cache.php → HTTP 200 with PHP source content. Identified vendor: ⟨vendor⟩ This is doubly problematic: 1. The drop-in's source code leaks (the user-installed cache plugin's version + structure → CVE matching is trivial). 2. The web server is serving raw .php source for at least this file — indicates PHP-FPM / FastCGI is not configured to handle the path, OR a server-misconfig is bypassing PHP execution. Other .php files in /wp-content/ may be affected the same way.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: CM.L2-3.4.7
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 4.8
- **compliance_v2 / iso_27001_2022**: A.8.9

## Run only this check

```
wpsecscan only object_cache_dropin https://example.com
```

`only` runs this check alone and prints its findings.
