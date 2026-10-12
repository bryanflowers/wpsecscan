---
id: algolia_elastic_frontend_keys
title: "Algolia / ES write-key leak in frontend JS (A14)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Other"
words: 99
---

# Algolia / ES write-key leak in frontend JS (A14)

**check_id**: `algolia_elastic_frontend_keys`
**aggressive**: no
**category**: Other
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-798
**D3FEND**: D3-CRO

## What it does

A14 (v2.6.0) — Algolia / Elasticsearch write-key leak via frontend JS.

algoliasearch-wordpress publishes a search-only API key into the
frontend bundle (intentional, safe), but mis-configured installs push
the ADMIN key (write/delete access on the index) instead. Same story
for `elasticpress` when the operator copy-pastes the wrong key into
the plugin's Settings page.

Passive: scan the homepage + the plugin's known JS-config endpoints
for the canonical key-shaped strings and flag any value whose ACL
field reveals write/admin scope (Algolia keys are base64-encoded JSON
blobs that include the ACL).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/low | ⟨title⟩ | 1. Open the search-engine dashboard, list this key's ACL. 2. If it's anything other than `search` (Algolia) / `read-only` (ES/Meili/Typesense), REVOKE NOW and replace the frontend usage with a search-only key. 3. Confirm the plugin's Settings page separates the admin key (server-side .env) from the search key (frontend JS). |

## Evidence the check records

- ⟨title⟩: Engine: ⟨engine⟩ Key (first 16 chars): ⟨value⟩... Admin-scope detected: ⟨is_admin⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only algolia_elastic_frontend_keys https://example.com
```

`only` runs this check alone and prints its findings.
