---
id: mobile_app_endpoints
title: "Mobile-app association discovery (#38)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 55
---

# Mobile-app association discovery (#38)

**check_id**: `mobile_app_endpoints`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: low
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#38 — Mobile-app endpoint discovery check.

Wraps mobile_app_discovery.discover and reports any universal-link
endpoints + Android app packages found in the target's
`.well-known/apple-app-site-association` / `assetlinks.json` files.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low/info | Mobile-app association files: ⟨count⟩ found, ⟨count⟩ endpoint(s) | Review the listed endpoints — these are the URL patterns the official mobile app intercepts via universal links. If any are auth-required, ensure the same checks apply when the URL is accessed via a desktop browser (not just the app). |
| info | Mobile-app discovery — no association files found | No action. |

## Evidence the check records

- Mobile-app association files: ⟨count⟩ found, ⟨count⟩ endpoint(s): Files: ⟨value⟩ Endpoints / packages: ⟨value⟩ ... +⟨value⟩ more
- Mobile-app discovery — no association files found: Neither apple-app-site-association nor assetlinks.json present.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only mobile_app_endpoints https://example.com
```

`only` runs this check alone and prints its findings.
