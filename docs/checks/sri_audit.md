---
id: sri_audit
title: "Subresource Integrity (SRI) audit (#B24)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 66
---

# Subresource Integrity (SRI) audit (#B24)

**check_id**: `sri_audit`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1195.002 — Compromise Software Supply Chain
**CWE**: CWE-353
**D3FEND**: D3-SCM

## What it does

Round-62 #B24 — Subresource Integrity (SRI) audit.

For every &lt;script src&gt; and &lt;link rel="stylesheet" href&gt; from a different
origin, check whether `integrity=` is set. Missing SRI on a CDN resource
means an attacker controlling the CDN (or successful BGP hijack / cache
poisoning) can swap the code for arbitrary JS/CSS.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | SRI missing on ⟨count⟩ cross-origin resource(s) | Add `integrity="sha384-..."` + `crossorigin="anonymous"` to every cross-origin &lt;script&gt; / &lt;link rel=stylesheet&gt;. Generate with `curl -sL <url> \| openssl dgst -sha384 -binary \| openssl base64 -A` |
| low | SRI present but using sha256 (⟨count⟩ resource(s)) | Upgrade to sha384 — recommended baseline for SRI (sha256 still acceptable but defence-in-depth). |
| low | SRI present without `crossorigin` attr on ⟨count⟩ resource(s) | Add `crossorigin="anonymous"` — without it, the SRI check may silently fail on cross-origin resources. |
| info | SRI audit — all cross-origin resources are integrity-protected | No action. |
| info | SRI audit — no home page | No action. |

## Evidence the check records

- SRI audit — all cross-origin resources are integrity-protected: Checked ⟨count⟩ &lt;script&gt; + ⟨count⟩ &lt;link stylesheet&gt;.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SI-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.h
- **compliance_v2 / cmmc**: SI.L2-3.14.6
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only sri_audit https://example.com
```

`only` runs this check alone and prints its findings.
