---
id: rest_namespace_leak
title: "REST namespace internal-name leak"
severity_max: low
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 87
---

# REST namespace internal-name leak

**check_id**: `rest_namespace_leak`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information

## What it does

Detect internal hostnames / staging IDs in REST namespace strings.

Each WordPress plugin registers REST routes via `register_rest_route()`
with a chosen namespace. The full namespace list is published at
/wp-json/. Some plugins/teams embed environment names or internal service
identifiers in namespace strings (e.g. `prod-east-1/v1`,
`staging-api/v2`, `my-internal-service/v1`) — leaks topology info.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | REST namespace(s) leak internal/staging identifiers (⟨count⟩) | Audit which plugin registered each namespace and check whether the internal name is intentional. If a staging-only plugin shipped to production, deactivate it. If the namespace is legitimate but leaks topology, rename it in the plugin source. |

## Evidence the check records

- REST namespace(s) leak internal/staging identifiers (⟨count⟩): /wp-json/ namespaces contain internal-shaped tokens: ⟨lines⟩ These come directly from plugin `register_rest_route()` calls and sometimes embed CI/CD artifact names, environment identifiers, or internal service names that should not be public.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.7
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan only rest_namespace_leak https://example.com
```

`only` runs this check alone and prints its findings.
