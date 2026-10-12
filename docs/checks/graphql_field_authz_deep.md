---
id: graphql_field_authz_deep
title: "GraphQL field-level authz deep probe (#70)"
severity_max: high
severity_dynamic: true
aggressive: false
category: "GraphQL & APIs"
words: 63
---

# GraphQL field-level authz deep probe (#70)

**check_id**: `graphql_field_authz_deep`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: high (some findings take their severity at run time)
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-285
**D3FEND**: D3-MFA

## What it does

GraphQL field-level authorization deep probe.

Round-64 #70 — wpgraphql.py already flags introspection-enabled
endpoints. This deep variant goes further: it tries to read specific
sensitive fields without authentication. WPGraphQL exposes `users`,
`mediaItems`, `comments`, `posts.author.email` etc. Many sites lock
top-level introspection but forget to lock individual fields' resolvers.

## Request footprint

The module contains 2 request call(s) to the target (POST x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (high, medium) | GraphQL: unauthenticated read of sensitive field `⟨sentinel_field⟩` | Restrict `⟨sentinel_field⟩` to authenticated callers in WPGraphQL. Use `graphql_resolve_field` filter or the `wpgraphql_disable_field` setting to require auth. Disable introspection in production: add `'show_in_graphql' => false` for sensitive types. |

## Evidence the check records

- GraphQL: unauthenticated read of sensitive field `⟨sentinel_field⟩`: POST ⟨endpoint⟩ returned populated `⟨sentinel_field⟩` without authentication. Why: ⟨why⟩

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only graphql_field_authz_deep https://example.com
```

`only` runs this check alone and prints its findings.
