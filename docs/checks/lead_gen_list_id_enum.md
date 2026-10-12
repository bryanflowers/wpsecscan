---
id: lead_gen_list_id_enum
title: "Klaviyo / Mailchimp list-ID enumeration (A12)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 147
---

# Klaviyo / Mailchimp list-ID enumeration (A12)

**check_id**: `lead_gen_list_id_enum`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: low
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1589 — Gather Victim Identity Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

A12 (v2.6.0) — Klaviyo / Mailchimp public list-ID enumeration.

Lead-gen plugins (Klaviyo for WP, Mailchimp for WP / MC4WP, OptinMonster,
ConvertKit) embed the public list/audience ID into the frontend form.
That ID is intentionally public, but several plugins ALSO expose a
subscriber-count endpoint or accept arbitrary list_id values in the
subscribe POST, which leaks:

  • Which audiences exist on this site (competitive intel).
  • Subscriber count per audience (via differential timing or 200/404
    on probe).

Passive: extract list-ID values from form HTML + probe the common
count endpoints. Surface medium when count differential is observable.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | Lead-gen plugin list/audience IDs visible in frontend HTML: ⟨count⟩ found | 1. For each list, confirm it's intended for public sign-up. 2. In the subscribe endpoint, validate the list_id is in an explicit allow-list (don't trust the POSTed value). 3. Enable Klaviyo/Mailchimp double-opt-in to block spam-subscriber bots. |

## Evidence the check records

- Lead-gen plugin list/audience IDs visible in frontend HTML: ⟨count⟩ found: List IDs leaked into the rendered page: ⟨value⟩ These IDs are intentionally public, but the operator may want to audit: - whether each list is meant to accept anonymous subscribes - whether the subscribe POST can be replayed with arbitrary list_id

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: AC-6
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only lead_gen_list_id_enum https://example.com
```

`only` runs this check alone and prints its findings.
