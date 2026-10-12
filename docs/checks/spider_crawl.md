---
id: spider_crawl
title: "Spider — recursive link crawler (#18)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 89
---

# Spider — recursive link crawler (#18)

**check_id**: `spider_crawl`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1593 — Search Open Websites/Domains
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#18 — spider check: runs the crawler + reports the URL inventory.

Reports the number of URLs discovered, depth-of-deepest-page, and any
robots.txt-blocked paths. Stashes the URL list in ctx['shared']['urls']
so later checks can consume it.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Spider crawled ⟨count⟩ URL(s) (max depth ⟨deepest⟩) | No action — informational. Use --no-spider if you want only the hard-coded path list (faster but less coverage). |
| info | Spider — no URLs crawled | No action. |

## Evidence the check records

- Spider crawled ⟨count⟩ URL(s) (max depth ⟨deepest⟩): First 20 discovered URLs: ⟨value⟩ ... and ⟨value⟩ more ⟨count⟩ URL(s) skipped due to robots.txt Disallow. ⟨value⟩ fetch error(s). Downstream checks can now probe these URLs instead of just the homepage.
- Spider — no URLs crawled: Couldn't fetch / or no internal links were found.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CA.L2-3.12.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.5
- **compliance_v2 / iso_27001_2022**: A.5.36

## Run only this check

```
wpsecscan only spider_crawl https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
