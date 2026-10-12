---
id: activitypub_data_leak
title: "ActivityPub actor PII leak probe (F8)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 54
---

# ActivityPub actor PII leak probe (F8)

**check_id**: `activitypub_data_leak`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

F8 (v2.8.1) — ActivityPub/Fediverse PII leak probe.

The WP ActivityPub plugin exposes per-user actor JSON at
`/@username` or `/wp-json/activitypub/1.0/users/<id>`. If author
email or other private fields leak in the actor doc, it's a
privacy regression even if the user opted into federation.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F8: ActivityPub actor doc leaks fields (⟨count⟩) | Update ActivityPub plugin &gt;= 5.1.0. Verify privacy settings: Settings → ActivityPub → Profile → minimal-disclosure. |
| info | F8: ActivityPub plugin not detected | No action needed. |

## Evidence the check records

- F8: ActivityPub plugin not detected: No ActivityPub actor JSON at /wp-json/activitypub/1.0/users/1

## Compliance mapping

- **compliance_map / pci_dss**: 3.4
- **compliance_map / nist_800_53**: SC-28
- **compliance_map / iso_27001**: A.8.11
- **compliance_v2 / hitrust**: 06.d
- **compliance_v2 / cmmc**: MP.L2-3.8.1
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.11

## Run only this check

```
wpsecscan only activitypub_data_leak https://example.com
```

`only` runs this check alone and prints its findings.
