# Upload SVG-XXE/polyglot/TOCTOU (#28-30)

**check_id**: `upload_bypass_deep`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-434
**D3FEND**: D3-IVA

## What it does

#28 + #29 + #30 — file-upload bypass deep dive.

#28 SVG / PDF / image XXE chain — embed <image href="file:///..."/> in SVG
#29 Polyglot files — gif89a+PHP, PDF+JS
#30 TOCTOU on upload — race the check-then-rename window

We probe common upload endpoints (WP media library, GF/CF7/WC product image).
Aggressive only.

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
wpsecscan --target https://example.com --only upload_bypass_deep
```
