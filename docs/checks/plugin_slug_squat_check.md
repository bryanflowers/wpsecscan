---
id: plugin_slug_squat_check
title: "Plugin slug-squatting (wp.org author drift) (F70)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 177
---

# Plugin slug-squatting (wp.org author drift) (F70)

**check_id**: `plugin_slug_squat_check`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A08:2021 — Software & Data Integrity
**MITRE ATT&CK**: T1195.001 — Compromise Software Dependencies
**CWE**: CWE-1357
**D3FEND**: D3-SBA

## What it does

F70 (v2.8.3) — plugin slug-squatting on the WP.org repository.

When a plugin is removed from wp.org and the slug is later re-
registered under a DIFFERENT author, every WP install with that
plugin starts auto-updating to the new (potentially malicious)
author's code. This is the same supply-chain class as PyPI
typosquatting.

We cache each detected plugin's `author` field from the wp.org API
in `~/.wpsecscan/cache/wporg/`. On subsequent scans, if the author
has changed since last seen, we emit a high-severity finding.

Defensive — first run just populates the cache (no findings unless
a delta is detected).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | F70: plugin slug-squat candidate — `⟨slug⟩` author changed | Verify whether the change is legitimate (plugin sold, author renamed) by checking the wp.org changelog and the plugin's GitHub. If unverified, DEACTIVATE the plugin immediately and manually inspect the latest update for code changes. |
| info | F70: no detected plugins to slug-check | No action needed. |
| info | F70: slug-squat check ran on ⟨checked⟩ plugin(s); no author changes | No action needed. |

## Evidence the check records

- F70: no detected plugins to slug-check: ctx['shared']['plugins'] empty — run after the `plugins` check.
- F70: slug-squat check ran on ⟨checked⟩ plugin(s); no author changes: Compared current wp.org `author` field against cached values for ⟨checked⟩ plugin(s).
- F70: plugin slug-squat candidate — `⟨slug⟩` author changed: wp.org author for `⟨slug⟩` was `⟨prior_author⟩` at last scan; current is `⟨current_author⟩`. This is the pattern used in real WP supply-chain attacks (the slug is re-registered under a different author after the original plugin is delisted).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.31
- **compliance_v2 / hitrust**: 10.h
- **compliance_v2 / cmmc**: SI.L2-3.14.6
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.8.31

## References

- https://api.wordpress.org/plugins/info/1.0/

## Run only this check

```
wpsecscan only plugin_slug_squat_check https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
