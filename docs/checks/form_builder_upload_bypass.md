---
id: form_builder_upload_bypass
title: "Form-builder file-upload bypass advisory (A23)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 100
---

# Form-builder file-upload bypass advisory (A23)

**check_id**: `form_builder_upload_bypass`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1505.003 — Web Shell
**CWE**: CWE-434
**D3FEND**: D3-FA

## What it does

A23 (v2.6.0) — Form-builder file-upload allow-list bypass detection.

Gravity Forms, WPForms, Formidable Forms, Ninja Forms, and Fluent
Forms all shipped at least one CVE in 2024-2025 where the file-upload
field's MIME / extension allow-list could be bypassed (double-extension
trick, MIME-spoofing via the Form Builder's pre-validated list, etc.).

Passive: fingerprint the plugin via homepage HTML, then surface a
medium advisory recommending version check + the canonical fix.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Form-builder plugin detected (⟨value⟩) — verify file-upload patch | 1. Confirm plugin versions are current (use wp-admin → Plugins). 2. Audit any form with a file-upload field: confirm the allow-list uses extension AND MIME AND magic-byte checks (not just extension). 3. Add a WAF rule blocking POSTs to /wp-content/uploads/ paths that don't go through the plugin's expected handler. 4. If you don't use file uploads, REMOVE the field from every form. |

## Evidence the check records

- Form-builder plugin detected (⟨value⟩) — verify file-upload patch: Detected plugin(s): ⟨value⟩. All listed plugins shipped CVEs in 2024-2025 around file-upload allow-list bypasses (double-extension, MIME spoofing, TOCTOU on the tmp_name). Manual version verification recommended.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only form_builder_upload_bypass https://example.com
```

`only` runs this check alone and prints its findings.
