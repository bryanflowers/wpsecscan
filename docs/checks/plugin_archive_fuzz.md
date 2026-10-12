---
id: plugin_archive_fuzz
title: "Plugin source-archive fuzz (#6)"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "WordPress core, plugins & themes"
words: 128
---

# Plugin source-archive fuzz (#6)

**check_id**: `plugin_archive_fuzz`
**aggressive**: yes
**category**: WordPress core, plugins & themes
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1530 — Data from Cloud Storage
**CWE**: CWE-538
**D3FEND**: D3-RAC

## What it does

#6 (from wpscan --enumerate dbe) — dot-extension archive fuzz.

For every detected plugin slug, probes `/wp-content/plugins/<slug>.<ext>`
across common archive formats. A developer who zipped the plugin folder
for backup and uploaded it to the web root is one of the most common
ways production sites accidentally leak full plugin source.

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Plugin source archives exposed — ⟨count⟩ backup(s) reachable | Delete the archive files from the web root. Then prevent recurrence: - Nginx: `location ~ \.(zip\|tar\|gz\|tgz\|rar\|7z\|bak\|old\|backup)$ { deny all; }` - Move backup workflow OUT of the web root (use `wp-cli db export ../backups/` with `..` to escape the doc root, or `rclone` to S3) |
| info | Plugin archive fuzz — no exposed backups (⟨count⟩ slugs × ⟨count⟩ extensions probed) | No action. |
| info | Plugin archive fuzz — no plugins detected | No action. |

## Evidence the check records

- Plugin source archives exposed — ⟨count⟩ backup(s) reachable: ⟨value⟩ ... (+more) Downloading a plugin .zip leaks the FULL source (including any hard-coded API keys, DB credentials, license tokens) and gives an attacker offline vulnerability research time.
- Plugin archive fuzz — no plugins detected: The `plugins` check didn't enumerate any slugs to fuzz against.
- Plugin archive fuzz — no exposed backups (⟨count⟩ slugs × ⟨count⟩ extensions probed): None of the slug.{zip,tar,gz,rar,7z,sql.gz,bak,old} variants returned a non-trivial body.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only plugin_archive_fuzz https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
