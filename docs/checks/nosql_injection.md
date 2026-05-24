# NoSQL operator injection probe

**check_id**: `nosql_injection`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-943
**D3FEND**: D3-IVA

## What it does

NoSQL injection probe (MongoDB-style operators).

Most WP sites use MySQL, but a growing number of plugins use Mongo/Couch via
add-on databases. This check sends MongoDB-operator-shaped payloads:
  - `?param[$ne]=null` (operator injection in PHP arrays)
  - JSON body `{"username": {"$ne": null}, "password": {"$ne": null}}`
  - `{"$where": "1==1"}` (server-side JavaScript injection)

A response that LOOKS DIFFERENT from the bare-parameter baseline indicates the
operator was consumed.

Aggressive-only.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only nosql_injection
```
