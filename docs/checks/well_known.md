---
id: well_known
title: "/.well-known/ resource enumeration"
severity_max: low
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 83
---

# /.well-known/ resource enumeration

**check_id**: `well_known`
**aggressive**: no
**category**: File & directory exposure
**max severity**: low
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low/info | Well-known resource exposed: ⟨path⟩ | If intentional (SSO, mobile app, federation), no action. If you don't know what this is, the plugin/theme that added it is the culprit — removing the plugin removes the file. Sensitive configs (openid-configuration, jwks.json) reveal your auth architecture. |
| info | No /.well-known/ resources exposed | No action. |

## Evidence the check records

- No /.well-known/ resources exposed: Probed ⟨count⟩ well-known paths; none returned a non-empty 200.
- Well-known resource exposed: ⟨path⟩: HTTP ⟨status⟩ (⟨size⟩ bytes). ⟨label⟩

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
wpsecscan only well_known https://example.com
```

`only` runs this check alone and prints its findings.
