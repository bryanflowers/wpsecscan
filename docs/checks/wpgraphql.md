---
id: wpgraphql
title: "WPGraphQL endpoint audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 207
---

# WPGraphQL endpoint audit

**check_id**: `wpgraphql`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: high
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

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | WPGraphQL accepts mutations from unauthenticated clients | Wrap mutations behind capability checks. For registerUser specifically, follow WPGraphQL's auth recipes: https://www.wpgraphql.com/docs/authentication-and-authorization Disable specific mutations via the graphql_register_types filter. |
| high/medium | WPGraphQL discloses ⟨count⟩ user(s) unauthenticated with EMAIL | Restrict the users root field to authenticated requests: add_filter('graphql_user_query_args', function($args, $source, $input, $context, $info){ if (!is_user_logged_in()) throw new \GraphQL\Error\UserError('auth required'); return $args; }, 10, 5); |
| medium | WPGraphQL accepts batched queries (DoS amplification vector) | Update WPGraphQL to the latest version (recent releases cap batch size by default). Or disable batching with the graphql_request_data filter. |
| medium | WPGraphQL introspection is enabled | In WPGraphQL → Settings, set 'Public Introspection Enabled' to OFF for production. Or in code: add_filter('graphql_introspection_enabled', '__return_false'); |
| info | WPGraphQL endpoint live at ⟨live_endpoint⟩ | No action needed by itself — see follow-up findings for any misconfigurations. |
| info | WPGraphQL endpoint not detected | No action needed (WPGraphQL is not in use, or it's mounted at a custom path). |

## Evidence the check records

- WPGraphQL endpoint live at ⟨live_endpoint⟩: POST ⟨live_endpoint⟩ with `{__typename}` returned a GraphQL response envelope.
- WPGraphQL endpoint not detected: Probed ⟨count⟩ known WPGraphQL paths. None responded with a GraphQL data envelope.
- WPGraphQL introspection is enabled: POST ⟨live_endpoint⟩ with `{__schema{types{name}}}` returned the full schema. Attackers can use introspection to map every query, mutation, and custom type — saves them hours of recon.
- WPGraphQL accepts mutations from unauthenticated clients: POST ⟨live_endpoint⟩ with a registerUser mutation was processed (no auth error). The mutation may have been validated and rejected on application logic, but the gate isn't auth.
- WPGraphQL accepts batched queries (DoS amplification vector): POST ⟨live_endpoint⟩ with a 20-query JSON array returned a list response. Attackers can amplify a single HTTP request into many DB queries.
- WPGraphQL discloses ⟨count⟩ user(s) unauthenticated with EMAIL: POST ⟨live_endpoint⟩ with `{users{nodes{name slug email}}}` returned ⟨count⟩ record(s). Sample: ⟨value⟩ Email addresses are present — phishing-ready dataset.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/graphql -X POST -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}'
# Disable introspection (functions.php):
# add_filter('graphql_introspection_enabled', '__return_false');
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- https://www.wpgraphql.com/docs/authentication-and-authorization

## Run only this check

```
wpsecscan only wpgraphql https://example.com
```

`only` runs this check alone and prints its findings.
