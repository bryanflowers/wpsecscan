# Error-page fingerprinting

**check_id**: `error_pages`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.002 — Software

## What it does

Error-page fingerprinting.

Probe a deliberately-bad URL and inspect the resulting error response for
disclosed server stack: Apache/Nginx version, PHP version, framework
debug-mode indicators (Symfony, Laravel, Django all have characteristic
error pages).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-11
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only error_pages
```
