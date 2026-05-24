# SSRF probes

**check_id**: `ssrf`
**aggressive**: yes
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1090 — Proxy

## What it does

SSRF probes via WP/plugin endpoints that fetch URLs.

Common SSRF vectors:
  - oEmbed proxy `/wp-json/oembed/1.0/proxy?url=...`
  - WP image proxy or plugin endpoints (`/wp-json/<plugin>/v1/fetch?url=...`)
  - REST API edge cases

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.21
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.6
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 12.6
- **compliance_v2 / iso_27001_2022**: A.8.16

## Run only this check

```
wpsecscan --target https://example.com --only ssrf
```
