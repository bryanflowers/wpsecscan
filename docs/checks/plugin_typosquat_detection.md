---
id: plugin_typosquat_detection
title: "Plugin slug typosquat detection (#58)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 72
---

# Plugin slug typosquat detection (#58)

**check_id**: `plugin_typosquat_detection`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1195.001 — Compromise Software Dependencies and Development Tools
**CWE**: CWE-1357
**D3FEND**: D3-SCM

## What it does

Plugin typosquat detection — compare installed slugs vs top wp.org names.

Round-64 #58 — attackers publish plugins with names one or two
characters away from a popular plugin ("yost-seo" vs "yoast-seo") hoping
admins install the wrong one. We compare each installed-plugin slug
against a curated top-50 wp.org list using Levenshtein distance, and
flag any near-but-not-exact match.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Possible plugin typosquat: ⟨installed_slug⟩ vs ⟨looks_like⟩ | Verify the installed plugin ⟨installed_slug⟩ is what you intended. Typosquat plugins often bundle the legitimate plugin's functionality PLUS a backdoor. If you meant to install ⟨looks_like⟩, uninstall the typosquat first, then install the canonical wp.org version. |

## Evidence the check records

- Possible plugin typosquat: ⟨installed_slug⟩ vs ⟨looks_like⟩: Installed: ⟨installed_slug⟩ Looks like top-plugin: ⟨looks_like⟩ Levenshtein distance: ⟨distance⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SA-12
- **compliance_map / iso_27001**: A.8.30

## Run only this check

```
wpsecscan only plugin_typosquat_detection https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
