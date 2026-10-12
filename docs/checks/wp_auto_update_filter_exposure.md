---
id: wp_auto_update_filter_exposure
title: "Public auto-update state exposure (F7)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Other"
words: 77
---

# Public auto-update state exposure (F7)

**check_id**: `wp_auto_update_filter_exposure`
**aggressive**: no
**category**: Other
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

F7 (v2.8.1) — WP auto-update filter exposure probe.

WordPress exposes the auto-update state per-plugin via
`/wp-json/wp/v2/plugins?_fields=auto_update`. If that endpoint is
publicly listable without auth, attackers learn which plugins are
NOT on auto-update and prioritise CVE exploitation for those.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F7: ⟨count⟩ plugin(s) have auto-update OFF and the state is publicly listable | Require auth for /wp-json/wp/v2/plugins (`disable_listing` filter on `rest_endpoints`). Either turn auto-update ON for the listed plugins, or block public REST plugin listing entirely. |

## Evidence the check records

- F7: ⟨count⟩ plugin(s) have auto-update OFF and the state is publicly listable: Public REST plugins list returned ⟨count⟩ plugins; ⟨count⟩ have auto_update=false. Example: ⟨value⟩. Combined with public version disclosure, attackers can prioritise CVE exploitation against the stale ones.

## Compliance mapping

- **compliance_map / pci_dss**: 1.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.4
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.1
- **compliance_v2 / iso_27001_2022**: A.5.15

## Run only this check

```
wpsecscan only wp_auto_update_filter_exposure https://example.com
```

`only` runs this check alone and prints its findings.
