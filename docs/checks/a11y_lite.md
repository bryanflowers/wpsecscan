# Accessibility smoke check

**check_id**: `a11y_lite`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

Lightweight accessibility (a11y) smoke check.

NOT a replacement for axe-core or Lighthouse — just a quick "is this site
missing the basics" check. Three rules:
  1. <html> must have lang=
  2. All <img> on the homepage must have alt= (empty alt is OK; missing isn't)
  3. The page must have a <title>

Why ship this? ADA Title III (US) and EU EAA (June 2025) increasingly turn
basic a11y misses into legal liability. Scanner users who run wpsecscan on
their own sites benefit from a heads-up.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: n/a
- **compliance_map / iso_27001**: n/a

## Run only this check

```
wpsecscan --target https://example.com --only a11y_lite
```
