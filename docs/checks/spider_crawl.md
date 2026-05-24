# Spider — recursive link crawler (#18)

**check_id**: `spider_crawl`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1593 — Search Open Websites/Domains
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#18 — spider check: runs the crawler + reports the URL inventory.

Reports the number of URLs discovered, depth-of-deepest-page, and any
robots.txt-blocked paths. Stashes the URL list in ctx['shared']['urls']
so later checks can consume it.

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
wpsecscan --target https://example.com --only spider_crawl
```
