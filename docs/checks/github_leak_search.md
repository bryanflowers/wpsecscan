---
id: github_leak_search
title: "GitHub leaked-token search (opt-in)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 134
---

# GitHub leaked-token search (opt-in)

**check_id**: `github_leak_search`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1552.001 — Credentials in Files
**CWE**: CWE-798
**D3FEND**: D3-CR

## What it does

GitHub leaked-token search.

Queries GitHub's code-search API for the target's domain combined with common
secret prefixes (`AKIA`, `sk_live_`, `ghp_`, etc). If anything's been committed,
GitHub finds it.

Opt-in: requires `--github-search-token` (a GitHub PAT with `public_repo` scope).
The PAT is needed because the code-search API requires auth.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Possible ⟨label⟩ leak: ⟨host⟩ mentioned in ⟨repo⟩/⟨path⟩ | 1. Open the link above and read the file. 2. If it's a real key — rotate it RIGHT NOW (Stripe / AWS / GitHub / etc). 3. Run `git log --all --full-history -p -- <file>` to confirm the key isn't still in the repo history (rotation invalidates the key but git history retains it). |
| info | GitHub code-search clean for ⟨host⟩ | No action. |
| info | GitHub leaked-token search skipped (no PAT) | No action. |

## Evidence the check records

- GitHub leaked-token search skipped (no PAT): Pass --github-search-token YOUR_PAT to enable. PAT needs `public_repo` scope. GitHub's code-search API requires auth (60 req/hour for the search endpoint).
- GitHub code-search clean for ⟨host⟩: Ran ⟨count⟩ secret-prefix queries; no matches.
- Possible ⟨label⟩ leak: ⟨host⟩ mentioned in ⟨repo⟩/⟨path⟩: GitHub code-search returned ⟨count⟩ match(es) for `⟨host⟩` AND a ⟨label⟩ prefix. First match: ⟨html_url⟩ This DOES NOT prove a real key is leaked — the match could be a placeholder, a comment, or coincidence — but it's a HIGH-PRIORITY manual check.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.308(a)(4)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: IA-5
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.a
- **compliance_v2 / cmmc**: IA.L2-3.5.10
- **compliance_v2 / nist_csf**: PR.DS-01
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.10

## References

- primary: https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
- https://api.github.com/search/code?
- https://github.com/search?q=

## Run only this check

```
wpsecscan only github_leak_search https://example.com
```

`only` runs this check alone and prints its findings.
