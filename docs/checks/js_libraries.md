# JS library version audit

**check_id**: `js_libraries`
**aggressive**: no
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1059.007 — JavaScript Execution

## What it does

JavaScript library version detection.

Scan response bodies for popular JS libraries (jQuery, jQuery UI, lodash,
underscore, AngularJS, Bootstrap, Moment.js) and flag versions with known
vulnerabilities.

Detection happens via three patterns:
  1. Filename-versioned URLs (e.g. `/jquery-3.5.1.min.js`)
  2. `?ver=` query strings on WP-enqueued assets
  3. Inline-script version comments (`/* jQuery v1.12.4 */`)

A7 (round-Q): after the local CVE-cutoff check, ALSO query OSV.dev for richer,
real-time CVE matching. OSV.dev has no API token requirement.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.j
- **compliance_v2 / cmmc**: SR.L2-3.17.1
- **compliance_v2 / nist_csf**: ID.SC-04
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.5.21

## Run only this check

```
wpsecscan --target https://example.com --only js_libraries
```
