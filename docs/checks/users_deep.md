# Deep user enumeration — 10 sources (#5)

**check_id**: `users_deep`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1589.002 — Email Addresses
**CWE**: CWE-200
**D3FEND**: D3-RAC

## What it does

#5 (from wpscan) — wide user-enumeration with 10 sources.

The existing `users` check covers ?author=, REST /wp/v2/users, and a couple
of others. wpscan probes ~10 paths to catch the long tail. This check fills
the gap.

Sources covered:
  1. ?author=N redirect (handled by existing `users` check)
  2. /wp-json/wp/v2/users
  3. /wp-json/oembed/1.0/embed?url=/?p=1   (extracts `author_name`)
  4. /feed/ (RSS — pulls `<dc:creator>` tags)
  5. /comments/feed/
  6. /wp-sitemap-users-1.xml
  7. /author-sitemap.xml
  8. Yoast SEO author archive at /sitemap_index.xml → author-sitemap.xml
  9. .well-known/security.txt (sometimes lists "responsible disclosure to")
 10. Comment-author HTML scraping from `/?p=1` (the rendered post page)

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: AC-2
- **compliance_map / iso_27001**: A.8.5
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.1
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan --target https://example.com --only users_deep
```
