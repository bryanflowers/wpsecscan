# WPGraphQL endpoint audit

**check_id**: `wpgraphql`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WPGraphQL endpoint audit.

The WPGraphQL plugin ships its own attack surface independent of the REST API.
Common misconfigurations:
  - Introspection enabled in production (any attacker can map the full schema)
  - Unauthenticated user enumeration via the `users` root query
  - Mutations accessible without auth (rare but catastrophic)
  - Batch queries enabled → DoS amplification

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only wpgraphql
```
