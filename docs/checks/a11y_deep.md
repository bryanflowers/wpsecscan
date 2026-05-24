# WCAG 2.2 accessibility deep audit (#24)

**check_id**: `a11y_deep`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-1004
**D3FEND**: D3-NTA

## What it does

Round-60 #24 — WCAG 2.2 accessibility deep audit.

Extends `a11y_lite` with full WCAG 2.2 success-criteria coverage:
images-without-alt, form-labels, heading order, focus-visible, colour
contrast (approximate — only flags pages with no contrast meta), aria
roles + landmarks, document language, redundant link text, etc.

Pure HTML parsing — no headless browser. Lists pages that fail and
groups by criterion ID.

## Compliance mapping

- **compliance_map / pci_dss**: 12.1
- **compliance_map / nist_800_53**: PL-1
- **compliance_map / iso_27001**: A.5.31
- **compliance_extra / hipaa**: 164.520
- **compliance_extra / soc2**: CC1.4
- **compliance_extra / fedramp**: PL-1
- **compliance_extra / gdpr**: Article 12
- **compliance_v2 / hitrust**: 11.a
- **compliance_v2 / cmmc**: PL.L2-3.15.2
- **compliance_v2 / nist_csf**: GV.PO-01
- **compliance_v2 / cis_v8**: 14.1
- **compliance_v2 / iso_27001_2022**: A.5.10

## Run only this check

```
wpsecscan --target https://example.com --only a11y_deep
```
