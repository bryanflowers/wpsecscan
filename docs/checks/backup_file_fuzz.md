# Backup-file long-tail fuzzer

**check_id**: `backup_file_fuzz`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery
**CWE**: CWE-538
**D3FEND**: D3-RAC

## What it does

H7 Backup-file long-tail fuzzer.

Existing `exposed_files` and `backup_exposure` checks cover the common cases
(`wp-config.php.bak`, `.git/config`, etc.). This fuzzer extends the tail with
~30 less-common variants that often slip through.

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
wpsecscan --target https://example.com --only backup_file_fuzz
```
