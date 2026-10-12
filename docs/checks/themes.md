---
id: themes
title: "Theme enumeration"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 100
---

# Theme enumeration

**check_id**: `themes`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: info
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software Discovery

## What it does

Theme enumeration.

Fetches / and extracts theme slugs from /wp-content/themes/&lt;slug&gt;/ asset URLs
in the HTML. For up to ten slugs it requests /wp-content/themes/&lt;slug&gt;/
style.css and reads the Version header when the file contains "Theme Name".
The slug-to-version map is stored in ctx['shared']['themes'] for later
checks. One info finding lists every theme and its version; nothing is
emitted when the homepage fails or shows no theme paths. Fix: keep all
installed themes updated, and delete unused ones, because inactive themes
remain reachable by URL. At most 11 GET requests.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | ⟨count⟩ theme(s) discovered via HTML asset paths | Keep all installed themes updated, including inactive ones. Delete unused themes — inactive themes still receive PHP execution if a CVE lands. |

## Evidence the check records

- ⟨count⟩ theme(s) discovered via HTML asset paths: Theme slugs found: ⟨lines⟩

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/wp-content/themes/<slug>/style.css | head -10
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only themes https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
