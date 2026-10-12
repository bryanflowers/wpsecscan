---
id: gdpr_dsr
title: "GDPR Data-Subject-Request audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 125
---

# GDPR Data-Subject-Request audit

**check_id**: `gdpr_dsr`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592.001 — Gather Victim Host Information: Hardware

## What it does

GDPR Data-Subject-Request (DSR) disclosure audit.

Probes common privacy-page URLs and looks for evidence the site advertises a
DSR / "right of access" / contact-the-DPO process. Under GDPR Art. 12-15, EU
sites MUST tell visitors how to exercise data rights — and many WP sites
quietly miss this.

Purely defensive: GET-only, no auth, no parameters.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Privacy page at ⟨p⟩ is missing a Data-Subject-Request process | Add a section to the privacy page explaining how to request data access / deletion / portability, with a contact email or web form. GDPR Art. 12 requires the process to be 'easily accessible and easy to understand'. |
| low | No privacy / GDPR page found at the usual paths | Publish a privacy notice at /privacy/ (or equivalent) that names the data controller, the legal bases for processing, the retention periods, and HOW visitors can exercise their rights (access, erasure, portability). Required by GDPR Art. 13-14 for any EU traffic. |
| info | Privacy page at ⟨p⟩ mentions DSR concepts (⟨count⟩ phrase(s) matched) | No immediate action — verify the page also has an actual contact channel for requests. |

## Evidence the check records

- No privacy / GDPR page found at the usual paths: Probed: ⟨value⟩
- Privacy page at ⟨p⟩ is missing a Data-Subject-Request process: Found a page at ⟨p⟩ but none of the expected DSR phrases appeared in the first 20 KB. Phrases looked for: 'data subject', 'right of access', 'right to erasure', 'DPO', 'request your data', etc.
- Privacy page at ⟨p⟩ mentions DSR concepts (⟨count⟩ phrase(s) matched): Matched phrases: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: PT-2
- **compliance_map / iso_27001**: A.5.34
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: MP.L1-3.8.3
- **compliance_v2 / nist_csf**: GV.OC-04
- **compliance_v2 / cis_v8**: 3.1
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan only gdpr_dsr https://example.com
```

`only` runs this check alone and prints its findings.
