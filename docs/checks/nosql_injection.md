---
id: nosql_injection
title: "NoSQL operator injection probe"
severity_max: high
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 131
---

# NoSQL operator injection probe

**check_id**: `nosql_injection`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: high
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

## Request footprint

The module contains 4 request call(s) to the target (GET x1, POST x3). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | NoSQL operator injection candidate at ⟨where⟩ | Cast all auth-form inputs to STRING before query-building. Reject inputs whose type is array/object. For WP, this is unusual — the relevant plugins are MongoCMS, WP-Cassandra and similar; audit them. |
| info | No NoSQL operator injection detected | No action. |
| info | NoSQL injection probe skipped (requires --aggressive) | No action. |

## Evidence the check records

- NoSQL injection probe skipped (requires --aggressive): This sends MongoDB-operator payloads to login + search endpoints.
- No NoSQL operator injection detected: MongoDB-style $ne / $where payloads against login + REST API didn't change response shapes.
- NoSQL operator injection candidate at ⟨where⟩: ⟨evidence⟩ If the underlying store is MongoDB or a similar NoSQL backend, an attacker can construct `{'$ne': null}` to match any user, bypassing password verification.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/www-community/Injection_Theory
- deep dive: https://book.hacktricks.xyz/pentesting-web/nosql-injection

## Run only this check

```
wpsecscan only nosql_injection https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
