---
id: wp_multisite_deep
title: "WP-Multisite per-blog deep audit (#17)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 51
---

# WP-Multisite per-blog deep audit (#17)

**check_id**: `wp_multisite_deep`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-RAC

## What it does

Round-60 #17 — WP-Multisite per-blog deep audit.

Enumerates network sites via /wp-json/wp/v2/sites and probes each
sub-blog for: distinct admin users, distinct plugin set, distinct
options, cross-tenant REST data leakage.

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ user(s) reachable from multiple sub-blogs | Audit super-admin grants. Multisite super admins are network-wide — minimise count. |
| low | Multisite suspected but /wp-json/wp/v2/sites unreachable | If you operate a multisite, expose `/wp-json/wp/v2/sites` to authenticated admins. |
| info | Multisite REST returned no sites | No action. |
| info | Multisite network with ⟨count⟩ sub-site(s) | Per-blog isolation is hard. Audit user_roles, plugins active per blog, and REST permissions. |
| info | WP Multisite deep — single-site install (skipped) | No action. |

## Evidence the check records

- Multisite suspected but /wp-json/wp/v2/sites unreachable: GET /wp-json/wp/v2/sites -&gt; ⟨value⟩
- WP Multisite deep — single-site install (skipped): No multisite markers found.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.1
- **compliance_v2 / iso_27001_2022**: A.5.15

## Run only this check

```
wpsecscan only wp_multisite_deep https://example.com
```

`only` runs this check alone and prints its findings.
