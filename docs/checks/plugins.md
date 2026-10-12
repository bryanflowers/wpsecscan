---
id: plugins
title: "Plugin enumeration"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 129
---

# Plugin enumeration

**check_id**: `plugins`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software Discovery

## What it does

Plugin enumeration.

GETs /, /?p=1, /wp-login.php, /feed/, /sample-page/ and /?page_id=2, and
extracts plugin slugs from /wp-content/plugins/&lt;slug&gt;/ asset URLs, taking the
?ver= value as the version when present. For up to 30 slugs it requests
readme.txt and reads the Stable tag. Reports an info finding listing all
plugins, or an info finding if none appear, plus a medium finding when any
readme.txt is public. The slug-to-version map is stored in
ctx['shared']['plugins'] for the CVE checks. Fix: keep plugins updated,
remove unused ones and block /wp-content/plugins/*/readme.txt.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨count⟩ plugin(s) expose readme.txt with version | Block /wp-content/plugins/*/readme.txt at the server level. Public readme files leak exact plugin versions, making CVE matching trivial. |
| info | No plugins discovered via HTML enumeration | Either plugins are masked (good) or the site is light on plugins. No action needed. |
| info | ⟨count⟩ plugin(s) discovered via HTML asset paths | Plugin slugs being discoverable is normal but useful to attackers. Keep all listed plugins updated. Consider a WAF that strips ?ver= asset query strings. |

## Evidence the check records

- ⟨count⟩ plugin(s) discovered via HTML asset paths: Plugin slugs found across ⟨pages_seen⟩ probed page(s): ⟨plugin_lines⟩
- No plugins discovered via HTML enumeration: Probed ⟨pages_seen⟩ page(s); no /wp-content/plugins/&lt;slug&gt;/ references found.
- ⟨count⟩ plugin(s) expose readme.txt with version: readme.txt accessible for: ⟨readme_lines⟩

## Suggested fix

Block plugin readme.txt files. Where to apply it: nginx server block.

```nginx
location ~ ^/wp-content/plugins/.+/readme\.txt$ { deny all; }
location ~ ^/wp-content/plugins/.+/readme\.md$ { deny all; }
```

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/wp-content/plugins/<slug>/readme.txt | head -20
# To enumerate definitively, log in and visit /wp-admin/plugins.php
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
wpsecscan only plugins https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
