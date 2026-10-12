---
id: backup_file_fuzz
title: "Backup-file long-tail fuzzer"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 45
---

# Backup-file long-tail fuzzer

**check_id**: `backup_file_fuzz`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery
**CWE**: CWE-538
**D3FEND**: D3-RAC

## What it does

H7 Backup-file long-tail fuzzer.

Existing `exposed_files` and `backup_exposure` checks cover the common cases
(`wp-config.php.bak`, `.git/config`, etc.). This fuzzer extends the tail with
~30 less-common variants that often slip through.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high | Backup-file fuzzer — ⟨count⟩ sensitive file(s) reachable | Block these patterns in your web server config. Nginx example: location ~ \.(bak\|swp\|tmp\|orig\|save\|old\|copy\|disabled\|dev\|staging\|production)$ { deny all; } location ~ /\.(git\|vscode\|idea\|DS_Store\|svn) { deny all; } location = /wp-config.php { deny all; } Apache equivalent in .htaccess: &lt;FilesMatch "\.(bak\|swp\|tmp\|orig\|save\|old\|copy)$"&gt; Require all denied &lt;/FilesMatch&gt; |
| info | Backup-file fuzzer — clean (⟨count⟩ variants probed) | No action. |

## Evidence the check records

- Backup-file fuzzer — clean (⟨count⟩ variants probed): No backup / IDE / editor files reachable.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 09.l
- **compliance_v2 / cmmc**: MP.L2-3.8.6
- **compliance_v2 / nist_csf**: PR.DS-11
- **compliance_v2 / cis_v8**: 11.3
- **compliance_v2 / iso_27001_2022**: A.8.13

## Run only this check

```
wpsecscan only backup_file_fuzz https://example.com
```

`only` runs this check alone and prints its findings.
