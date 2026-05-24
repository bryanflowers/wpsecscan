# Backup-plugin file exposure

**check_id**: `backup_exposure`
**aggressive**: no
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
wpsecscan --target https://example.com --only backup_exposure
```
