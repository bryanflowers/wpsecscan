# WordPress Multisite audit

**check_id**: `multisite`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

WordPress Multisite audit.

Multisite (Network) installations have extra attack surface: the network admin,
signup forms, sunrise.php drop-in, and per-site subdirectory/subdomain access.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.18

## Run only this check

```
wpsecscan --target https://example.com --only multisite
```
