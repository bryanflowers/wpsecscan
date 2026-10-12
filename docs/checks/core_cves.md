---
id: core_cves
title: "Core CVE matching"
severity_max: info
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 65
---

# Core CVE matching

**check_id**: `core_cves`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: info (some findings take their severity at run time)
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WordPress core CVE matching against the Wordfence Intelligence DB.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | No known core CVEs match installed WordPress ⟨ver⟩ | No action needed for core. Keep auto-updates enabled. |
| info | Vulnerability database is empty — skipping core CVE match | Run `wpsecscan --update-db` or click 'Refresh DB' in the GUI. |
| info | WordPress core version unknown — cannot match CVEs | No action needed. |
| varies | WordPress core ⟨ver⟩ affected by ⟨value⟩: ⟨value⟩ | Update WordPress core to ⟨value⟩ via Dashboard → Updates. Test in staging if you run heavy plugins. |

## Evidence the check records

- WordPress core version unknown — cannot match CVEs: The core_version check did not detect a version (good for security, blind for CVE matching).
- Vulnerability database is empty — skipping core CVE match: No cached or embedded vulnerability database found.
- No known core CVEs match installed WordPress ⟨ver⟩: DB source: ⟨source⟩; ⟨count⟩ entries checked.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# Compare your installed version to the advisory:
wp core version
wp core check-update
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.i
- **compliance_v2 / cmmc**: RA.L2-3.11.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only core_cves https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
