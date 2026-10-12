---
id: git_dir_deep_scan
title: "Deep .git directory enumeration (#66)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 97
---

# Deep .git directory enumeration (#66)

**check_id**: `git_dir_deep_scan`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery
**CWE**: CWE-538
**D3FEND**: D3-FCR

## What it does

Deep .git directory enumeration.

Round-64 #66 — existing git_exposure.py flags an exposed .git/config.
This deep variant tries to actually walk .git/HEAD → .git/refs/heads/* →
.git/objects/* to estimate how much of the repo an attacker could
reconstruct. Even partial reconstruction often leaks credentials.

## Request footprint

The module contains 5 request call(s) to the target (GET x5). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | .git/HEAD readable — likely full repo reconstructible | Block /.git/* publicly: Apache: RedirectMatch 404 /\.git Nginx: location ~ /\.git { deny all; return 404; } Then audit the repo for committed secrets (gitleaks, trufflehog) — assume an attacker has them. |
| critical | .git/index readable — full filename inventory leaked | An attacker can enumerate every file in the repo from .git/index. Block /.git/* publicly NOW. |
| critical | Branch refs reachable — `git-dumper` style reconstruction possible | Any object reachable from this SHA can be reconstructed by an attacker. See https://github.com/arthaud/git-dumper. |
| critical | Credentials embedded in .git/config remote URL | ROTATE the credentials immediately. Block /.git/* publicly. |

## Evidence the check records

- .git/HEAD readable — likely full repo reconstructible: GET /.git/HEAD -&gt; 200 Contents: ⟨head_text⟩
- Credentials embedded in .git/config remote URL: Found: ⟨value⟩...
- Branch refs reachable — `git-dumper` style reconstruction possible: Got commit SHA from refs/heads: ⟨ref_text⟩
- .git/index readable — full filename inventory leaked: GET /.git/index -&gt; 200, ⟨count⟩ bytes, DIRC magic confirmed

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## References

- https://github.com/arthaud/git-dumper

## Run only this check

```
wpsecscan only git_dir_deep_scan https://example.com
```

`only` runs this check alone and prints its findings.
