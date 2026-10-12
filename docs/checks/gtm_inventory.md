---
id: gtm_inventory
title: "Google Tag Manager container inventory"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 126
---

# Google Tag Manager container inventory

**check_id**: `gtm_inventory`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: low
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1593 — Search Open Websites/Domains

## What it does

Detect Google Tag Manager container IDs in page source.

GTM containers (GTM-XXXXXXX) are not themselves secrets, but cataloguing
them publicly helps two things:
  1. Privacy inventory — every GTM container can fire arbitrary third-party
     JS, so it's a per-page list of "what else gets executed in my visitors'
     browsers".
  2. Dev / staging leakage — a staging GTM container left live in production
     ships analytics events to the wrong destination AND tells competitors
     you have a separate staging container.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low/info | Google Tag Manager container ID(s) in page source: ⟨count⟩ found | Audit each container in tagmanager.google.com — verify ownership and intentional deployment. Remove any from disused/legacy installations. For privacy inventories, document each container's purpose and the third-party JS it loads (each GTM tag = another data-exfil vector that bypasses your CSP). |

## Evidence the check records

- Google Tag Manager container ID(s) in page source: ⟨count⟩ found: Container IDs detected in homepage HTML: ⟨value⟩ Multiple containers on one page is unusual — verify each is intentional. A staging-account container left in production ships analytics events to the wrong place and reveals dev infrastructure.

## Compliance mapping

- **compliance_map / pci_dss**: 12.8.1
- **compliance_map / nist_800_53**: SA-12
- **compliance_map / iso_27001**: A.5.19
- **compliance_v2 / hitrust**: 05.h
- **compliance_v2 / cmmc**: RA.L2-3.11.1
- **compliance_v2 / nist_csf**: ID.SC-01
- **compliance_v2 / cis_v8**: 15.1
- **compliance_v2 / iso_27001_2022**: A.5.19

## References

- https://tagmanager.google.com/#/container/accounts/_/containers/_/workspaces/_/tags?gtmContainerId=

## Run only this check

```
wpsecscan only gtm_inventory https://example.com
```

`only` runs this check alone and prints its findings.
