---
id: wp_builder_audit
title: "Block-theme/FSE + page-builder audit (#1-2)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 106
---

# Block-theme/FSE + page-builder audit (#1-2)

**check_id**: `wp_builder_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

Round-59 #1-2 — Block-theme/FSE + page-builder audit.

#1 Block theme / Full-Site-Editing audit — detect FSE themes, read
   `templates/`, `parts/`, `theme.json`. Surface custom block patterns
   that ship JavaScript with `wp_enqueue_script` calls and check for
   versions with known stored-XSS in `save()` markup.
#2 Page-builder fingerprint + known-vulnerable-version match for
   Elementor, Divi, Beaver Builder, WPBakery, Bricks, Oxygen. These
   are the highest-CVE-density plugins in the entire WP ecosystem.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨name⟩ ⟨version⟩ below patched baseline ⟨min_safe⟩ | Update ⟨name⟩ to ⟨min_safe⟩ or later — older versions have public RCE/stored-XSS CVEs. |
| info | Block theme / FSE active (⟨count⟩ indicator(s)) | FSE themes expose template + template-part REST endpoints. Confirm /wp-json/wp/v2/templates returns 401/403 to anonymous users — otherwise template HTML may be edited via REST. |
| info | Builder/FSE audit — no FSE indicators, no builders detected | No action. |
| info | Page builders detected (⟨count⟩) | Cross-reference each builder version against its CVE history (the bundled CVE DB does this for plugins, not themes). |

## Evidence the check records

- Block theme / FSE active (⟨count⟩ indicator(s)): Reachable: ⟨value⟩
- Builder/FSE audit — no FSE indicators, no builders detected: Probed FSE endpoints + 7 popular builders.
- ⟨name⟩ ⟨version⟩ below patched baseline ⟨min_safe⟩: ⟨path⟩ reports version ⟨version⟩; baseline ⟨min_safe⟩ (pre-patch).

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_extra / hipaa**: 164.308(a)(1)
- **compliance_extra / soc2**: CC7.1
- **compliance_extra / fedramp**: CM-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only wp_builder_audit https://example.com
```

`only` runs this check alone and prints its findings.
