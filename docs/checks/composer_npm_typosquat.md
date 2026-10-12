---
id: composer_npm_typosquat
title: "Composer/npm typosquat dep advisory (A34)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 104
---

# Composer/npm typosquat dep advisory (A34)

**check_id**: `composer_npm_typosquat`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1195.001 — Compromise Software Dependencies
**CWE**: CWE-1357
**D3FEND**: D3-SBA

## What it does

A34 (v2.6.0) — composer.lock / package-lock.json typosquat advisory.

When the existing `composer_lock_audit` / `yarn_pnpm_lock_audit` checks
find a reachable lock file, parse the dependency names and surface a
medium advisory for names that look like known-bad typosquats of
popular packages.

We don't ship the full typosquat dictionary (it's tens of thousands of
entries; should be a separate data file). Instead we apply a small
high-signal heuristic: any composer/npm dep name that differs from a
top-100 popular package by 1 character (Levenshtein-1) AND isn't in the
top-100 itself.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Typosquat-candidate dependency in ⟨path⟩ | 1. For each near-match, confirm via packagist.org / npmjs.com that the dep is legitimate. 2. Cross-check against socket.dev or snyk.io typosquat feed for known-malicious matches. 3. If suspicious, pin to a known-good package and re-install. |

## Evidence the check records

- Typosquat-candidate dependency in ⟨path⟩: Reachable lock file contains package names suspiciously close to popular packages: ⟨value⟩ ...

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.2
- **compliance_map / nist_800_53**: SR-3
- **compliance_map / iso_27001**: A.8.30

## Run only this check

```
wpsecscan only composer_npm_typosquat https://example.com
```

`only` runs this check alone and prints its findings.
