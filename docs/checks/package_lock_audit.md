---
id: package_lock_audit
title: "package-lock.json exposure + CVE check (#60)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 83
---

# package-lock.json exposure + CVE check (#60)

**check_id**: `package_lock_audit`
**aggressive**: no
**category**: File & directory exposure
**max severity**: high
**OWASP**: A06:2021 — Vulnerable & Outdated Components
**MITRE ATT&CK**: T1592.002 — Software
**CWE**: CWE-1104
**D3FEND**: D3-SU

## What it does

package-lock.json / yarn.lock / pnpm-lock.yaml exposure audit.

Round-64 #60 — themes + build pipelines often leave Node lockfiles in
the docroot. Same risk profile as composer.lock: discloses every
dependency + exact version, plus the resolved registry URL (which may
itself include an auth token).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Known-vulnerable npm dep: ⟨name⟩@⟨ver⟩ | npm update ⟨name⟩ (must be &gt; ⟨max_vuln⟩) |
| high | npm registry auth token leaked in resolved URL | Rotate the npm/GitHub token immediately. Block public access to the lockfile. |
| medium/low | npm dependency file exposed at ⟨path⟩ | Block public access to package*.json / yarn.lock / pnpm-lock.yaml. Apache: &lt;FilesMatch "^(package(-lock)?\.json\|yarn\.lock\|pnpm-lock\.yaml)$"&gt; Require all denied &lt;/FilesMatch&gt; Nginx: location ~* ^/(package(-lock)?\.json\|yarn\.lock\|pnpm-lock\.yaml)$ { deny all; } |

## Evidence the check records

- npm dependency file exposed at ⟨path⟩: GET ⟨path⟩ -&gt; 200 (⟨count⟩ bytes)
- npm registry auth token leaked in resolved URL: Found pattern ⟨value⟩... in ⟨path⟩
- Known-vulnerable npm dep: ⟨name⟩@⟨ver⟩: ⟨path⟩ declares ⟨name⟩ @ ⟨ver⟩ CVE: ⟨ref⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.2
- **compliance_map / nist_800_53**: SI-2
- **compliance_map / iso_27001**: A.8.8

## Run only this check

```
wpsecscan only package_lock_audit https://example.com
```

`only` runs this check alone and prints its findings.
