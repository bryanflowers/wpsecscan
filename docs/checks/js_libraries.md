---
id: js_libraries
title: "JS library version audit"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Other"
words: 138
---

# JS library version audit

**check_id**: `js_libraries`
**aggressive**: no
**category**: Other
**max severity**: critical
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1059.007 — JavaScript Execution

## What it does

JavaScript library version detection.

Scan response bodies for popular JS libraries (jQuery, jQuery UI, lodash,
underscore, AngularJS, Bootstrap, Moment.js) and flag versions with known
vulnerabilities.

Detection happens via three patterns:
  1. Filename-versioned URLs (e.g. `/jquery-3.5.1.min.js`)
  2. `?ver=` query strings on WP-enqueued assets
  3. Inline-script version comments (`/* jQuery v1.12.4 */`)

A7 (round-Q): after the local CVE-cutoff check, ALSO query OSV.dev for richer,
real-time CVE matching. OSV.dev has no API token requirement.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical/high/medium | OSV.dev: ⟨name⟩ ⟨version⟩ has ⟨count⟩ known advisor⟨value⟩ | Update ⟨name⟩ to a version that's not affected. OSV.dev lists `fixed` versions for each advisory — pick the highest one mentioned and use that as the target. |
| medium | Outdated ⟨name⟩: ⟨installed⟩ (fixed in ⟨cutoff⟩) | Update ⟨name⟩ to ⟨cutoff⟩+. In WordPress, the bundled jQuery is updated via core; for theme-bundled JS, edit the theme's enqueue calls. For Bootstrap/Moment, the library is usually in the theme — check the theme's CSS/JS folders. |
| medium | ⟨name⟩ is end-of-life (⟨installed⟩ detected) | Migrate off ⟨name⟩. For AngularJS specifically, no upgrade path exists — move to Angular (TypeScript) or another framework. |
| info | Detected ⟨count⟩ JS librar(y/ies) in page source | No action needed. See per-library findings below for any with known CVEs. |
| info | No common JS libraries detected via filename / version-comment patterns | No action needed. (Sites that bundle JS via webpack/Vite typically obfuscate version strings.) |

## Evidence the check records

- Detected ⟨count⟩ JS librar(y/ies) in page source: Libraries discovered: ⟨summary_lines⟩
- No common JS libraries detected via filename / version-comment patterns: Scanned ⟨count⟩ pages.
- OSV.dev: ⟨name⟩ ⟨version⟩ has ⟨count⟩ known advisor⟨value⟩: OSV-cross-referenced — ⟨name⟩ ⟨version⟩: Advisory IDs: ⟨value⟩ CVEs: ⟨value⟩ Detail: https://osv.dev/list?q=⟨value⟩&ecosystem=npm
- ⟨name⟩ is end-of-life (⟨installed⟩ detected): ⟨name⟩ ⟨installed⟩ detected. ⟨value⟩
- Outdated ⟨name⟩: ⟨installed⟩ (fixed in ⟨cutoff⟩): Detected ⟨name⟩ ⟨installed⟩; vulnerable to: ⟨value⟩

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/ | grep -oE 'jquery[^"\']*\.js'
# Snyk: https://security.snyk.io/package/npm/jquery
# Retire.js: npx retire --js
```

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.3
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8
- **compliance_v2 / hitrust**: 06.j
- **compliance_v2 / cmmc**: SR.L2-3.17.1
- **compliance_v2 / nist_csf**: ID.SC-04
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.5.21

## References

- https://api.osv.dev/v1/query
- https://osv.dev/list?q=

## Run only this check

```
wpsecscan only js_libraries https://example.com
```

`only` runs this check alone and prints its findings.
