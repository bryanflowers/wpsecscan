# Mobile-app association discovery (#38)

**check_id**: `mobile_app_endpoints`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#38 — Mobile-app endpoint discovery check.

Wraps mobile_app_discovery.discover and reports any universal-link
endpoints + Android app packages found in the target's
`.well-known/apple-app-site-association` / `assetlinks.json` files.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only mobile_app_endpoints
```
