# /.well-known/ resource enumeration

**check_id**: `well_known`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Gather Victim Host Information: Client Configurations

## What it does

Comprehensive /.well-known/ enumeration.

RFC 8615 reserves /.well-known/ for site metadata. Many WordPress sites
expose more than they realise:
  - SSO discovery (openid-configuration, oauth-authorization-server)
  - Mobile app deep-link config (apple-app-site-association, assetlinks.json)
  - Matrix federation (matrix/server, matrix/client)
  - WebFinger (account discovery)
  - host-meta (XRD service docs)

This check is purely informational — we report what's exposed; the user
decides what's intentional.

## Compliance mapping

- **compliance_map / pci_dss**: 12.5
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.1
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: IR.L2-3.6.2
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan --target https://example.com --only well_known
```
