# GraphQL query-depth DoS probe

**check_id**: `graphql_field_dos`
**aggressive**: yes
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.002 — Endpoint Denial of Service: Service Exhaustion Flood

## What it does

GraphQL query-depth DoS probe.

Sends a deeply-nested introspection query (`{ __schema { types { fields { type
{ fields { ... }}}}}}` × N). If the server returns 200 with the full response,
no depth limit is enforced and an attacker can craft queries that scale
exponentially.

Aggressive-only (sends a moderately expensive query).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only graphql_field_dos
```
