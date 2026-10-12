---
id: a11y_deep
title: "WCAG 2.2 accessibility deep audit (#24)"
severity_max: info
severity_dynamic: true
aggressive: false
category: "Privacy, compliance & accessibility"
words: 78
---

# WCAG 2.2 accessibility deep audit (#24)

**check_id**: `a11y_deep`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: info (some findings take their severity at run time)
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | A11y deep — could not fetch home page | No action. |
| info | A11y deep — no obvious failures detected | Run an in-browser audit (axe-core / Lighthouse) for the criteria a static scan cannot evaluate. |
| varies | A11y WCAG 2.2 failures — ⟨count⟩ at ⟨sev⟩ | Each line names the WCAG criterion. See https://www.w3.org/WAI/WCAG22/quickref/ for guidance. |

## Evidence the check records

- A11y deep — no obvious failures detected: Checked WCAG 2.2 criteria 1.1.1, 1.3.1, 1.4.3, 2.4.1, 2.4.4, 2.4.6, 3.1.1, 4.1.2.

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

## References

- https://www.w3.org/WAI/WCAG22/quickref/

## Run only this check

```
wpsecscan only a11y_deep https://example.com
```

`only` runs this check alone and prints its findings.
