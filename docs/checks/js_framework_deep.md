---
id: js_framework_deep
title: "JS framework deep-detect + version pin (#B31)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 59
---

# JS framework deep-detect + version pin (#B31)

**check_id**: `js_framework_deep`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

Round-62 #B31 — JavaScript framework deep-detect with versions.

Detects React/Vue/Angular/Svelte/Next/Nuxt/Remix/Astro/Qwik/SolidJS by
parsing the home HTML for framework-specific markers, then extracts
versions from the main bundle URL when possible. Cross-references
versions against a minimum-safe-version pin list.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨name⟩ ⟨version⟩ below patched baseline ⟨min_safe⟩ | Upgrade ⟨name⟩ to ⟨min_safe⟩ or later. Cross-reference with the bundled CVE DB for specifics. |
| info | JS framework deep — no SPA frameworks detected | No action. |
| info | JS framework deep — no home page | No action. |
| info | JS frameworks detected: ⟨count⟩ | SPA frameworks bundle their own deps. Run `npm audit` or `pnpm audit` in your front-end repo. |

## Evidence the check records

- JS framework deep — no SPA frameworks detected: Probed ⟨count⟩ frameworks.
- ⟨name⟩ ⟨version⟩ below patched baseline ⟨min_safe⟩: Detected ⟨name⟩ ⟨version⟩; min-safe ⟨min_safe⟩.

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_extra / hipaa**: 164.308(a)(1)
- **compliance_extra / soc2**: CC7.1
- **compliance_extra / fedramp**: CM-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: CM.L2-3.4.6
- **compliance_v2 / nist_csf**: PR.PS-06
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only js_framework_deep https://example.com
```

`only` runs this check alone and prints its findings.
