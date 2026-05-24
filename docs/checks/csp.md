# CSP deep analysis

**check_id**: `csp`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1059.007 — Command and Scripting: JavaScript

## What it does

Deep CSP analysis.

The tls_headers check flags a missing CSP. This one *grades* a present CSP —
scoring usage of unsafe-inline, unsafe-eval, wildcard sources, and missing
directives that meaningfully harden the page.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.23

## Run only this check

```
wpsecscan --target https://example.com --only csp
```
