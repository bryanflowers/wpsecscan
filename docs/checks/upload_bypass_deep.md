---
id: upload_bypass_deep
title: "Upload SVG-XXE/polyglot/TOCTOU (#28-30)"
severity_max: high
severity_dynamic: false
aggressive: true
category: "SSRF / RCE / open access"
words: 97
---

# Upload SVG-XXE/polyglot/TOCTOU (#28-30)

**check_id**: `upload_bypass_deep`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-434
**D3FEND**: D3-IVA

## What it does

#28 + #29 + #30 — file-upload bypass deep dive.

#28 SVG / PDF / image XXE chain — embed &lt;image href="file:///..."/&gt; in SVG
#29 Polyglot files — gif89a+PHP, PDF+JS
#30 TOCTOU on upload — race the check-then-rename window

We probe common upload endpoints (WP media library, GF/CF7/WC product image).
Aggressive only.

## Request footprint

The module contains 1 request call(s) to the target (REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Upload endpoint accepts unauth POST: ⟨endpoint⟩ | WordPress media upload requires `manage_options` capability — this endpoint should reject anonymous POST. Audit `register_rest_route` permission_callback. |
| info | Upload-bypass deep dive skipped (passive) | No action. |
| info | Upload-bypass deep dive: endpoints correctly rejected unauth POST | No action. (Manual follow-up: if you have admin creds, repeat with `--auth-user` to test the post-auth bypass surface.) |

## Evidence the check records

- Upload-bypass deep dive skipped (passive): Pass --aggressive.
- Upload-bypass deep dive: endpoints correctly rejected unauth POST: Probed ⟨count⟩ known WP upload endpoints with SVG-XXE + polyglot payloads. None accepted.
- Upload endpoint accepts unauth POST: ⟨endpoint⟩: POST ⟨endpoint⟩ with SVG-XXE returned ⟨value⟩ without auth.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SC.L2-3.13.13
- **compliance_v2 / nist_csf**: PR.PS-04
- **compliance_v2 / cis_v8**: 10.5
- **compliance_v2 / iso_27001_2022**: A.8.7

## Run only this check

```
wpsecscan only upload_bypass_deep https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
