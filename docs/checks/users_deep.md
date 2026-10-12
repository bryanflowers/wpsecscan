---
id: users_deep
title: "Deep user enumeration — 10 sources (#5)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 144
---

# Deep user enumeration — 10 sources (#5)

**check_id**: `users_deep`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: medium
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

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/low | Deep user enumeration found ⟨count⟩ username(s) across ⟨count⟩ source(s) | 1. Block REST /wp/v2/users for unauth (jetpack module 'protect' or a one-line wp-content/mu-plugins filter) 2. Disable RSS feeds you don't use (`add_filter('feed_links_show_posts_feed', '__return_false')` etc.) 3. Configure Yoast / Rank Math to exclude author sitemaps if you don't publish multi-author content 4. Use display-names that differ from login-names so leaked display-names aren't usable for login |
| info | Deep user enumeration — no usernames disclosed | No action. |

## Evidence the check records

- Deep user enumeration found ⟨count⟩ username(s) across ⟨count⟩ source(s): Sources with data: ⟨value⟩ Usernames: ⟨value⟩ (+ ⟨value⟩ more) These names enable targeted brute-force / password-spray attacks against /wp-login.php.
- Deep user enumeration — no usernames disclosed: Checked oEmbed, RSS, comments feed, WP-core + Yoast author sitemaps, and post HTML. No usernames leaked.

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
wpsecscan only users_deep https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
