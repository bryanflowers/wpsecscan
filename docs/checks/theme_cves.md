---
id: theme_cves
title: "Theme CVE matching"
severity_max: info
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 78
---

# Theme CVE matching

**check_id**: `theme_cves`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: info (some findings take their severity at run time)
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Theme CVE matching against the Wordfence Intelligence DB.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | No known-vulnerable theme versions detected among ⟨count⟩ theme(s) | No action needed. |
| info | No themes to cross-reference against CVE database | No action needed. |
| info | Vulnerability database is empty — skipping theme CVE match | Run `wpsecscan --update-db` or click 'Refresh DB' in the GUI. |
| varies | Known vulnerability in theme ⟨slug⟩ ⟨value⟩: ⟨value⟩ | Update theme '⟨slug⟩' to ⟨value⟩ via Appearance → Themes. |

## Evidence the check records

- No themes to cross-reference against CVE database: The theme-enumeration check did not discover any theme slugs.
- Vulnerability database is empty — skipping theme CVE match: No cached or embedded vulnerability database found.
- No known-vulnerable theme versions detected among ⟨count⟩ theme(s): DB source: ⟨source⟩; ⟨count⟩ entries checked.
- Known vulnerability in theme ⟨slug⟩ ⟨value⟩: ⟨value⟩: Theme: ⟨slug⟩ Installed: ⟨value⟩ Fixed in: ⟨value⟩ CVE: ⟨value⟩ CVSS: ⟨value⟩ References: ⟨refs⟩

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
wp theme list --format=table
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
wpsecscan only theme_cves https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
