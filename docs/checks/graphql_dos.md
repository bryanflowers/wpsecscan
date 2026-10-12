---
id: graphql_dos
title: "GraphQL alias-amplification DoS"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 236
---

# GraphQL alias-amplification DoS

**check_id**: `graphql_dos`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.002 — Endpoint Denial of Service: Service Exhaustion Flood

## What it does

GraphQL DoS probes — alias amplification (always) + depth nesting (aggressive).

Discovers the GraphQL endpoint once, then runs:
  1. Alias amplification — sends the same field aliased 50 times. If the server
     accepts it without rejecting via a complexity/depth limit, an attacker
     can 50x backend CPU per HTTP request.
  2. Depth nesting (aggressive only) — sends a deeply-nested introspection
     query. If accepted, queries can be scaled exponentially.

Only runs when /graphql or /index.php?graphql exists.

## Request footprint

The module contains 4 request call(s) to the target (POST x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | GraphQL accepted a depth-⟨DEPTH⟩ introspection query at ⟨gql_path⟩ | Add a depth-limit. WPGraphQL has a built-in `query_depth` filter — set max ~10. Or use graphql-armor / graphql-cost-analysis if running custom graphql code. |
| medium | GraphQL alias amplification ACCEPTED at ⟨gql_path⟩ | Install a query-complexity / depth-limit middleware. For WPGraphQL: enable `graphql_request_data` filter with a max-query-depth limit (most plugins default to no limit). Reference: https://www.wpgraphql.com/docs/security/#query-depth |
| medium | GraphQL depth-⟨DEPTH⟩ query exhausted the connection at ⟨gql_path⟩ | Install a query-depth-limit middleware. For WPGraphQL: use the `graphql_request_data` filter to reject queries deeper than ~10. |
| info | GraphQL alias amplification REJECTED at ⟨gql_path⟩ | No action — your GraphQL endpoint correctly rejects amplification. |
| info | GraphQL alias amplification not effective at ⟨gql_path⟩ | No action. |
| info | GraphQL depth-⟨DEPTH⟩ query REJECTED at ⟨gql_path⟩ (good) | No action — depth-limit looks healthy. |
| info | No GraphQL endpoint detected — DoS probes skipped | No action. |

## Evidence the check records

- GraphQL alias amplification REJECTED at ⟨gql_path⟩: 50-aliased query returned HTTP ⟨code⟩ — query-complexity limit appears to be enforced.
- GraphQL alias amplification ACCEPTED at ⟨gql_path⟩: Single field: ⟨baseline_ms⟩ ms. ⟨ALIAS_COUNT⟩-aliased: ⟨aliased_ms⟩ ms. Cost ratio: ⟨cost_ratio⟩x. ⟨alias_hits⟩ aliases reflected in the response. An attacker can send 50 identical queries in one HTTP request, amplifying server CPU cost per round-trip.
- GraphQL alias amplification not effective at ⟨gql_path⟩: Aliased query cost ratio: ⟨cost_ratio⟩x — within tolerance.
- GraphQL depth-⟨DEPTH⟩ query exhausted the connection at ⟨gql_path⟩: No response after ⟨elapsed_ms⟩ ms — server either crashed or hit a default timeout.
- GraphQL accepted a depth-⟨DEPTH⟩ introspection query at ⟨gql_path⟩: Server returned 200 after ⟨elapsed_ms⟩ ms for a depth-⟨DEPTH⟩ nested query (no depth-limit middleware). An attacker can craft deeper queries that scale the per-request CPU cost exponentially.
- No GraphQL endpoint detected — DoS probes skipped: Probed: ⟨value⟩
- GraphQL depth-⟨DEPTH⟩ query REJECTED at ⟨gql_path⟩ (good): HTTP ⟨value⟩ after ⟨elapsed_ms⟩ ms — depth-limit appears enforced.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- https://www.wpgraphql.com/docs/security/#query-depth

## Run only this check

```
wpsecscan only graphql_dos https://example.com
```

`only` runs this check alone and prints its findings.
