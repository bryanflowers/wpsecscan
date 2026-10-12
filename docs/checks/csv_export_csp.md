---
id: csv_export_csp
title: "CSV-export formula-injection probe"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 156
---

# CSV-export formula-injection probe

**check_id**: `csv_export_csp`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: medium
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1204.002 — User Execution: Malicious File

## What it does

CSV-export formula-injection probe.

WordPress sites that expose `?export=csv` or `?action=export` endpoints
(WooCommerce orders, Contact Form 7 entries, Gravity Forms, etc.) often
serialize user-submitted content (names, comments, support tickets) verbatim
into CSV cells. If those cells begin with `=`, `+`, `-`, `@`, an admin
opening the export in Excel executes that as a formula.

Probe: POST a benign canary that begins with `=` to common form/comment
endpoints, then fetch the matching export and check whether the canary
arrived un-escaped.

Aggressive-only (does write a comment-like value).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | CSV export at ⟨p⟩ contains formula-prefixed cells | Sanitize CSV exports per OWASP CSV Injection: prefix any cell starting with =, +, -, @, tab, or CR with a single quote `'`. WordPress core's `wp_list_table::ajax_response()` doesn't do this — plugins must escape themselves. WooCommerce has had this issue patched since 4.0; older plugins may not. |
| info | CSV-export injection probe skipped (requires --aggressive) | No action. |
| info | No CSV-export formula injection found | No action. |

## Evidence the check records

- CSV-export injection probe skipped (requires --aggressive): This check requires --aggressive — it pulls and inspects export files.
- No CSV-export formula injection found: Probed ⟨count⟩ common export paths; none contained formula-prefixed cells.
- CSV export at ⟨p⟩ contains formula-prefixed cells: Cells starting with =/+/-/@: ⟨sample⟩ An admin opening this export in Excel or LibreOffice Calc will execute the leading character as a formula — DDE injection, ext command, or info leak.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only csv_export_csp https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
