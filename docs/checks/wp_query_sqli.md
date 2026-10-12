---
id: wp_query_sqli
title: "WP_Query/wpdb-specific SQLi (#4)"
severity_max: high
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 65
---

# WP_Query/wpdb-specific SQLi (#4)

**check_id**: `wp_query_sqli`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-89
**D3FEND**: D3-IVA

## What it does

#4 WP_Query / $wpdb-specific SQLi probes.

Targets WordPress-specific quirks the generic sqli check doesn't:
  - %d-formatted columns receiving non-numeric input (wpdb::prepare quirk)
  - $wpdb-&gt;prepare('LIKE %s', ...) where the value contains %% / _ /   - meta_query parameter pollution
  - tax_query parameter pollution

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | WP_Query SQLi — ⟨count⟩ payload(s) caused suspicious response | Audit `$wpdb->prepare()` calls in custom plugins / themes. Never interpolate user input into SQL without `%d` for ints + `%s` for strings. For meta_query / tax_query, use the array form, not the raw `meta_value` URL parameter. |
| info | WP_Query SQLi probes skipped (passive mode) | No action. |
| info | WP_Query SQLi probes — clean | No action. |

## Evidence the check records

- WP_Query SQLi probes skipped (passive mode): Pass --aggressive.
- WP_Query SQLi probes — clean: ⟨count⟩ WP-specific payload(s) tested; none altered the response.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan only wp_query_sqli https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
