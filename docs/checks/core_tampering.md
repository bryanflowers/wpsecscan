---
id: core_tampering
title: "Core file tampering check"
severity_max: critical
severity_dynamic: true
aggressive: true
category: "SSRF / RCE / open access"
words: 109
---

# Core file tampering check

**check_id**: `core_tampering`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1505.003 — Server Software Component: Web Shell

## What it does

Core file tampering / backdoor heuristic check.

Probes for files that should not exist in a stock WordPress install. Hits
on these paths are signs of either a broken plugin, an attacker-planted
webshell, or a forgotten admin script.

This is heuristic — false positives are possible for unusual themes that
legitimately put .php under /wp-content/uploads/. Reported severity tiers
the response so the user can quickly triage.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium, low, info) | Suspicious file present: ⟨value⟩ | 1. Open the file on the server and read it. If it contains ⟨_EV⟩(⟨_B64⟩(...)) or any obfuscated PHP — it's a webshell. 2. Compare with the same path on a clean WP of the same version: https://wordpress.org/download/release-archive/ 3. If unsure, remove the file and watch logs for what re-creates it. 4. Run a full malware scan (Wordfence, Patchstack, Sucuri SiteCheck) before declaring it safe. |
| info | No suspicious core-tampering paths found | No action needed. |

## Evidence the check records

- Suspicious file present: ⟨value⟩: ⟨evidence⟩ This path should not exist in a stock WP install. Verify whether it's a known good plugin drop-in or a tampered/back-doored file.
- No suspicious core-tampering paths found: Probed ⟨count⟩ known backdoor / tampering paths; all 404'd.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
# Compare a suspect file against the same path in a clean WP of your version:
# https://wordpress.org/download/release-archive/
# Or run Wordfence / Sucuri SiteCheck for a full malware sweep
curl -sI https://example.com/wp-content/uploads/shell.php
curl -sI https://example.com/wp-admin/install.php
```

## Compliance mapping

- **compliance_map / pci_dss**: 11.5.2
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.12
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 11.5
- **compliance_v2 / iso_27001_2022**: A.8.32

## References

- https://wordpress.org/download/release-archive/

## Run only this check

```
wpsecscan only core_tampering https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
