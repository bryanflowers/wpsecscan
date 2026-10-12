---
id: rest_schema_field_leak
title: "REST schema-callback field leak (O144)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 103
---

# REST schema-callback field leak (O144)

**check_id**: `rest_schema_field_leak`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

O144 (v2.6.0) — REST schema-callback field leak.

WordPress REST endpoints registered with a `schema` callback expose the
endpoint's full field structure via `OPTIONS /wp-json/.../endpoint`.
The schema response leaks internal field names + types even when the
GET would fail auth. Several plugins exposed admin-only field names
this way that helped attackers craft targeted UpdatePosts payloads.

Passive: OPTIONS the common REST collections + look for `schema` /
`properties` blocks in the response. Any unauth schema response that
reveals field names (e.g. `wp_admin_*`, `_internal_*`, `secret_*`)
gets flagged.

## Request footprint

The module contains 1 request call(s) to the target (REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | REST schema leaks internal/admin field names: ⟨path⟩ | 1. Audit register_rest_field calls for this endpoint; internal-only fields shouldn't be exposed in the schema. 2. Either gate the schema with show_in_rest=&gt;false for private fields, or split the endpoint into public + private REST namespaces. 3. Confirm the GET response itself doesn't return these fields unauthenticated (separate issue if it does). |

## Evidence the check records

- REST schema leaks internal/admin field names: ⟨path⟩: OPTIONS ⟨path⟩ → 200 + suspicious schema keys: ⟨value⟩ ...

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only rest_schema_field_leak https://example.com
```

`only` runs this check alone and prints its findings.
