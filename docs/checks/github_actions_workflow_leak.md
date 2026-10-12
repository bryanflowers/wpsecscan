---
id: github_actions_workflow_leak
title: "CI workflow YAML exposed on webroot (A35)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 101
---

# CI workflow YAML exposed on webroot (A35)

**check_id**: `github_actions_workflow_leak`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-538
**D3FEND**: D3-CRO

## What it does

A35 (v2.6.0) — .github/workflows/*.yml exposure on production webroot.

Some hosting setups serve the entire git tree, including `.github/`.
When the workflows directory is reachable, the YAML files leak:

  • Secret names (env: SECRET_KEY, env: DEPLOY_KEY) — attacker knows
    which secrets to target with phishing.
  • Branch names (`branches: [main, staging, demo]`) — attacker can
    guess subdomains / preview URLs.
  • Deployment scripts that reference internal hosts.

Probe canonical paths + flag medium when any 200-with-YAML response.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | CI workflow file web-reachable: ⟨path⟩ | 1. Add `Disallow: /.github/` to robots.txt (best-effort, not security). 2. In Apache: `<DirectoryMatch "\.git(hub)?"> Require all denied </DirectoryMatch>` 3. In nginx: `location ~ /\.git { deny all; return 404; }` 4. Long-term: deploy via CI artifact, not by checking out the .git tree to the web root. |

## Evidence the check records

- CI workflow file web-reachable: ⟨path⟩: GET ⟨path⟩ → HTTP 200, YAML-shaped body. Secret names leaked: ⟨value⟩ Branch names leaked: ⟨value⟩ First 300 bytes: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.3.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only github_actions_workflow_leak https://example.com
```

`only` runs this check alone and prints its findings.
