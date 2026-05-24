# REST method enumeration

**check_id**: `wp_rest_methods`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WP REST API method enumeration via OPTIONS.

For each REST namespace discovered by rest_api, send OPTIONS and look at the
Allow header. Plugins that register POST/PUT/DELETE endpoints sometimes forget
to gate them behind capability checks.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only wp_rest_methods
```
