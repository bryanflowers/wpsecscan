# CSV-export formula-injection probe

**check_id**: `csv_export_csp`
**aggressive**: yes
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only csv_export_csp
```
