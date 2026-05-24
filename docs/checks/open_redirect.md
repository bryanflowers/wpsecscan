# Open-redirect probes

**check_id**: `open_redirect`
**aggressive**: yes
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1204.001 — User Execution: Malicious Link

## What it does

Open-redirect probes on /wp-login.php?redirect_to= and common variants.

WP core's wp_safe_redirect() filters off-host destinations, but custom themes
and plugins sometimes ship their own redirect handlers that don't.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only open_redirect
```
