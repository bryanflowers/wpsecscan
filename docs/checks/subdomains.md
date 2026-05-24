# Subdomain discovery

**check_id**: `subdomains`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1590.005 — Gather Victim Network: IP Addresses

## What it does

Subdomain discovery via certificate transparency (crt.sh).

For each discovered subdomain, do a quick DNS resolve + HTTP probe to flag:
  - Subdomains pointing to dangling CDN providers (takeover candidates)
  - Subdomains exposing dev/staging/admin panels

## Compliance mapping

- **compliance_map / pci_dss**: 11.3.1
- **compliance_map / nist_800_53**: CA-8
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-04
- **compliance_v2 / cis_v8**: 1.1
- **compliance_v2 / iso_27001_2022**: A.5.9

## Run only this check

```
wpsecscan --target https://example.com --only subdomains
```
