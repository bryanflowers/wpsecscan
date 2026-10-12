---
id: yarn_pnpm_lock_audit
title: "yarn.lock / pnpm-lock.yaml exposure (#61)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 71
---

# yarn.lock / pnpm-lock.yaml exposure (#61)

**check_id**: `yarn_pnpm_lock_audit`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

yarn.lock + pnpm-lock.yaml exposure audit.

Round-64 #61 — companion to package_lock_audit.py for the non-npm Node
lockfile formats. Yarn 1.x writes plain-text (custom format), Yarn 2+
writes YAML, pnpm writes YAML. The risk profile is identical to
package-lock.json: dependency disclosure + occasional auth-token leaks.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Registry auth token leaked in lockfile resolved URL | Rotate the token IMMEDIATELY. Block public access to the lockfile. Consider a secret scanner in CI to prevent recurrence. |
| medium | ⟨kind⟩ exposed at ⟨path⟩ | Block public access to Node lockfiles: Apache: &lt;FilesMatch "^(yarn\|pnpm)-?(lock)?\.(ya?ml\|lock)$"&gt; Require all denied &lt;/FilesMatch&gt; Nginx: location ~* ^/(yarn\|pnpm)-?(lock)?\.(ya?ml\|lock)$ { deny all; } Then audit deps with `yarn audit` / `pnpm audit`. |

## Evidence the check records

- ⟨kind⟩ exposed at ⟨path⟩: GET ⟨path⟩ -&gt; 200 (⟨count⟩ bytes); valid ⟨kind⟩ signature
- Registry auth token leaked in lockfile resolved URL: Token pattern in ⟨path⟩: ⟨value⟩...

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.2
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only yarn_pnpm_lock_audit https://example.com
```

`only` runs this check alone and prints its findings.
