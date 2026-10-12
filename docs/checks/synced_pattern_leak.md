---
id: synced_pattern_leak
title: "Synced-pattern (block) public-leak probe (F9)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 65
---

# Synced-pattern (block) public-leak probe (F9)

**check_id**: `synced_pattern_leak`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1213 — Data from Information Repositories
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

F9 (v2.8.1) — Synced-pattern (formerly Reusable Block) content leak.

WP 6.3+ exposes synced patterns at `/wp-json/wp/v2/blocks`. By
default this requires the `edit_posts` capability, but some sites
have it filtered open. Public exposure leaks unpublished/private
content (drafts in patterns, sensitive snippets, etc.).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F9: /wp-json/wp/v2/blocks publicly returns ⟨count⟩+ synced patterns | Add to functions.php: `add_filter('rest_pre_dispatch', function($r,$s,$req){if(strpos($req->get_route(),'/wp/v2/blocks')!==false && !current_user_can('edit_posts')) return new WP_Error('rest_forbidden','',['status'=>401]); return $r;},10,3);` |

## Evidence the check records

- F9: /wp-json/wp/v2/blocks publicly returns ⟨count⟩+ synced patterns: Public unauthenticated GET returned synced-pattern data. Patterns may contain unpublished content, internal snippets, or sensitive drafts.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 06.d
- **compliance_v2 / cmmc**: MP.L2-3.8.1
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.11

## Run only this check

```
wpsecscan only synced_pattern_leak https://example.com
```

`only` runs this check alone and prints its findings.
