# Plugin source-archive fuzz (#6)

**check_id**: `plugin_archive_fuzz`
**aggressive**: yes
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

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan --target https://example.com --only plugin_archive_fuzz
```
