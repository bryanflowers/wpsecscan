---
id: core_checksums
title: "WP core file checksums vs wp.org manifest"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 126
---

# WP core file checksums vs wp.org manifest

**check_id**: `core_checksums`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1505 — Server Software Component

## What it does

WP core integrity via official wp.org checksums.

The existing core_tampering check uses pattern heuristics. This one is
authoritative: it downloads the official SHA-256 manifest from wp.org
for the detected core version and probes a small set of high-impact
core files via the public web tree (/wp-includes/version.php,
/wp-includes/load.php, etc.). Any file that returns 200 with a non-
matching SHA-256 = critical (webshell or backdoor in a core file).

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WP core file checksum mismatch (⟨count⟩ file(s) modified) | 1. STOP scheduled jobs and active editing on the site immediately — treat as an active incident. 2. Diff the modified file against the official version: `wp core verify-checksums --version=⟨wp_version⟩` (via wp-cli) or download the upstream file from https://github.com/WordPress/WordPress/tree/{wp_version} for comparison. 3. Once the modification is understood, restore from a known-good backup taken before the suspected compromise. Rotate all secrets (DB password, WP salts, plugin API keys). 4. Audit access logs to find the entry point — most core-file tampering is downstream of either a vulnerable plugin or a compromised admin account. |

## Evidence the check records

- WP core file checksum mismatch (⟨count⟩ file(s) modified): For WordPress ⟨wp_version⟩, these core files don't match the official wp.org SHA-256: ⟨lines⟩ A core-file checksum mismatch is one of the strongest indicators of compromise — backdoors, webshells, and credential-stealers are frequently planted in wp-includes/load.php or wp-includes/version.php. This finding is authoritative: the checksum source is wp.org itself, not a heuristic.

## Compliance mapping

- **compliance_map / pci_dss**: 11.5.2
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.32
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 11.5
- **compliance_v2 / iso_27001_2022**: A.8.32

## References

- https://api.wordpress.org/core/checksums/1.0/?version=
- https://github.com/WordPress/WordPress/tree/

## Run only this check

```
wpsecscan only core_checksums https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
