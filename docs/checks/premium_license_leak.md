# Premium plugin license-key leak scan (#7)

**check_id**: `premium_license_leak`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials in Files
**CWE**: CWE-798
**D3FEND**: D3-CR

## What it does

#7 (from wpscan) — premium plugin license-key leak.

Several commercial WP plugins (Elementor Pro, Yoast Premium, WP Rocket,
Gravity Forms, Beaver Builder, Easy Digital Downloads, WPMU DEV) store
their license key inside a settings file that occasionally gets bundled
into the page's enqueued JS / CSS / HTML output. When that happens, the
license key is exposed to every visitor and an attacker can use it on
their own install to get free updates / pirate the plugin.

We probe the homepage HTML + common admin-ajax enqueue paths for license-key
patterns (`license_key=`, `pro_license=`, `_license_status`, etc.).

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: IA-5
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.a
- **compliance_v2 / cmmc**: IA.L2-3.5.10
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.10

## Run only this check

```
wpsecscan --target https://example.com --only premium_license_leak
```
