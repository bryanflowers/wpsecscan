# Forced-browse hidden-path discovery (#21)

**check_id**: `forced_browse`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1083 — File and Directory Discovery
**CWE**: CWE-538
**D3FEND**: D3-RAC

## What it does

#21 (from ZAP / DirBuster) — forced-browse / hidden-path discovery.

Fans out a 200-entry curated wordlist (data/common_paths.txt) against the
target's web root. Anything that returns 200 / 301 / 302 with a non-trivial
body is reported as a discovered path the homepage didn't link to.

User can extend the wordlist by dropping additional lines into
~/.wpsecscan/extra_paths.txt — those are merged at load time.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CA.L2-3.12.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.5
- **compliance_v2 / iso_27001_2022**: A.5.36

## Run only this check

```
wpsecscan --target https://example.com --only forced_browse
```
