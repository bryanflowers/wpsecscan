---
id: forced_browse
title: "Forced-browse hidden-path discovery (#21)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 92
---

# Forced-browse hidden-path discovery (#21)

**check_id**: `forced_browse`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: critical
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

## Request footprint

The module contains 1 request call(s) to the target (HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Forced-browse: ⟨count⟩ CRITICAL hidden path(s) reachable | Block these paths immediately. Nginx pattern: location ~ /(wp-config\|\.env\|\.git\|phpinfo\|adminer\|phpmyadmin) { deny all; } |
| medium/low | Forced-browse: ⟨count⟩ other discovered path(s) | Review each — paths that should be public (like /robots.txt) are fine to leave; private ones (admin panels, backup dirs) should be blocked or require auth. |
| info | Forced-browse: clean (⟨count⟩ paths probed) | No action. |
| info | Forced-browse: empty wordlist | No action. |

## Evidence the check records

- Forced-browse: empty wordlist: data/common_paths.txt not readable.
- Forced-browse: clean (⟨count⟩ paths probed): No hidden paths returned 200/301/302/401/403.
- Forced-browse: ⟨count⟩ other discovered path(s): ⟨value⟩ ... and ⟨value⟩ more

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
wpsecscan only forced_browse https://example.com
```

`only` runs this check alone and prints its findings.
