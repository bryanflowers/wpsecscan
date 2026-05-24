# robots.txt / sitemap audit

**check_id**: `robots_sitemap`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1593.003 — Search Open Websites/Domains

## What it does

robots.txt + sitemap.xml intelligence.

Beyond just fetching them, mine them for:
  - Admin paths and staging URLs leaked via Disallow:
  - All discovered URLs via sitemap (great for finding admin-* pages,
    abandoned subdomains, leaked draft posts, etc.)
  - Sitemap that exposes media uploads, plugin upload paths, etc.

## Compliance mapping

- **compliance_map / pci_dss**: 12.5
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.1

## Run only this check

```
wpsecscan --target https://example.com --only robots_sitemap
```
