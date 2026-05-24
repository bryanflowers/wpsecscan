# GraphQL alias-amplification DoS

**check_id**: `graphql_dos`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.002 — Endpoint Denial of Service: Service Exhaustion Flood

## What it does

GraphQL query-aliasing DoS probe.

Sends a small batched query that ALIASES the same field 50 times. If the server
returns a 200 with the full 50-element response (rather than rejecting with a
complexity/depth limit), it's amplifying — an attacker can send one HTTP request
that costs the backend 50x normal CPU.

Only runs if /graphql or /index.php?graphql exists.

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
wpsecscan --target https://example.com --only graphql_dos
```
