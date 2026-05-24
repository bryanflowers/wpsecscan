# Block-theme/FSE + page-builder audit (#1-2)

**check_id**: `wp_builder_audit`
**aggressive**: no
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
wpsecscan --target https://example.com --only wp_builder_audit
```
