---
id: backup_exposure
title: "Backup-plugin file exposure"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "File & directory exposure"
words: 130
---

# Backup-plugin file exposure

**check_id**: `backup_exposure`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1530 — Data from Cloud Storage

## What it does

Backup-plugin exposure check.

Backup plugins are a top WordPress info-leak source — they all write to
predictable paths under wp-content, and operators frequently forget to
add web-server level deny rules.

Severity logic:
  - .sql / .sqlite / .wpress / wp-config-in-backup = critical (immediate DB credential leak)
  - .zip / .tar.gz of the site = high (full site source + secrets)
  - log files / readme = low (info disclosure but not catastrophic)

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, low) | Backup-plugin exposure: ⟨value⟩ | 1. **Right now**: delete the exposed files from the web root. 2. Block backup-plugin paths at the web server. Nginx example: location ~ ^/(wp-content/(updraft\|backups-dup-lite\|backups-dup-pro\|ai1wm-backups\|wpvividbackups\|uploads/backwpup-backups\|uploads/backupbuddy_backups\|uploads/wp-time-capsule\|uploads/xcloner-backups))(/.*)?$ { deny all; } 3. Audit the backup-plugin config to write OUTSIDE the docroot (S3, off-site). 4. Rotate every DB and WP secret that may have been in an exposed dump. |
| info | No backup-plugin exposure detected | No action needed. |

## Evidence the check records

- Backup-plugin exposure: ⟨value⟩: ⟨value⟩ Backup files left in the web root are one of the highest-impact WP info leaks — a SQL dump contains DB credentials and all user data; a site .zip contains every secret in wp-config.php.
- No backup-plugin exposure detected: Probed ⟨count⟩ common backup-plugin paths; none returned anything that looked like an exposed backup.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# Block backup paths at Nginx:
# location ~ ^/(wp-content/(updraft|backups-dup-lite|backups-dup-pro|ai1wm-backups|wpvividbackups|uploads/backwpup-backups|uploads/backupbuddy_backups))(/.*)?$ { deny all; }
curl -sI https://example.com/wp-content/updraft/
curl -sI https://example.com/wp-content/ai1wm-backups/
```

## Compliance mapping

- **compliance_map / pci_dss**: 9.4.1
- **compliance_map / nist_800_53**: CP-9
- **compliance_map / iso_27001**: A.5.33
- **compliance_v2 / hitrust**: 09.l
- **compliance_v2 / cmmc**: MP.L2-3.8.6
- **compliance_v2 / nist_csf**: PR.DS-11
- **compliance_v2 / cis_v8**: 11.3
- **compliance_v2 / iso_27001_2022**: A.8.13

## Run only this check

```
wpsecscan only backup_exposure https://example.com
```

`only` runs this check alone and prints its findings.
