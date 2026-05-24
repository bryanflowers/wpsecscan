# GitHub leaked-token search (opt-in)

**check_id**: `github_leak_search`
**aggressive**: no
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

## Run only this check

```
wpsecscan --target https://example.com --only github_leak_search
```
