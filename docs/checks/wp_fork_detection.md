---
id: wp_fork_detection
title: "WP fork detection (ClassicPress / Bedrock / headless)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 109
---

# WP fork detection (ClassicPress / Bedrock / headless)

**check_id**: `wp_fork_detection`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-RAC

## What it does

Item #19 — WordPress fork detection (ClassicPress, Bedrock layout, Roots, etc.).

Some checks assume vanilla WP file layout / REST behaviour and produce false
positives on a fork:
  - ClassicPress (no Gutenberg; v1.x is still a thing; reports as
    "ClassicPress" in the REST API generator field).
  - Bedrock (Roots) — `wp-config.php` lives in /config/, plugins live in
    `/app/plugins/`, themes in `/app/themes/`. Checks that probe
    `/wp-content/plugins/...` URLs find nothing.

This check posts one info finding identifying the fork (so reports show
context) and writes the fork type to `ctx['shared']['wp_fork']` so
downstream checks can adjust their assumptions.

## Request footprint

The module contains 4 request call(s) to the target (GET x2, HEAD x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | WP fork detection: vanilla WordPress | No action needed. |
| info | WP fork detection: ⟨fork⟩ | — |

## Evidence the check records

- WP fork detection: vanilla WordPress: No ClassicPress / Bedrock / headless markers detected.

## Compliance mapping

- **compliance_map / pci_dss**: 12.5.1
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only wp_fork_detection https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
