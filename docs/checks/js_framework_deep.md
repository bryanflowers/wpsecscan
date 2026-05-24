# JS framework deep-detect + version pin (#B31)

**check_id**: `js_framework_deep`
**aggressive**: no
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
wpsecscan --target https://example.com --only js_framework_deep
```
