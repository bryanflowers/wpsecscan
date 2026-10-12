---
id: premium_license_leak
title: "Premium plugin license-key leak scan (#7)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 192
---

# Premium plugin license-key leak scan (#7)

**check_id**: `premium_license_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Premium plugin license key leaked in page HTML (⟨count⟩ key(s)) | 1. Rotate the affected license keys in the plugin vendor's account dashboard. 2. Find the offending setting in wp-admin and remove it from any front-end enqueued scripts (search the codebase for `wp_localize_script` calls that pass the license value). 3. The plugin author should never have echoed the license to the public side — if it's a plugin you control, fix the leak upstream; if it's a third-party plugin, file a security report with the vendor. |
| info | Premium plugin license-key scan — clean | No action. |

## Evidence the check records

- Premium plugin license key leaked in page HTML (⟨count⟩ key(s)): ⟨value⟩ A leaked license key allows pirates to activate the plugin on their own install + receive automatic updates as if they had paid. The plugin vendor's license-server will eventually block the key, but until then the leaker pays for someone else's installs. Some vendors also use the license key as an auth token for support tickets — leaks can let third parties open tickets in your name.
- Premium plugin license-key scan — clean: Scanned ⟨count⟩ URL(s) against ⟨count⟩ known premium-plugin license patterns. No leakage.

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
wpsecscan only premium_license_leak https://example.com
```

`only` runs this check alone and prints its findings.
