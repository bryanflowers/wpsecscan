---
id: robots_sitemap
title: "robots.txt / sitemap audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "File & directory exposure"
words: 84
---

# robots.txt / sitemap audit

**check_id**: `robots_sitemap`
**aggressive**: no
**category**: File & directory exposure
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1593.003 — Search Open Websites/Domains

## What it does

robots.txt + sitemap.xml intelligence.

Beyond just fetching them, mine them for:
  - Admin paths and staging URLs leaked via Disallow:
  - All discovered URLs via sitemap (great for finding admin-* pages,
    abandoned subdomains, leaked draft posts, etc.)
  - Sitemap that exposes media uploads, plugin upload paths, etc.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Sitemap exposes ⟨count⟩ sensitive-looking URL(s) | Filter the sitemap to exclude admin, staging, and test URLs. In WP: `add_filter('wp_sitemaps_post_types', ...)` and similar filters; in Yoast/Rank Math, use the exclusion settings. |
| low | robots.txt advertises ⟨count⟩ sensitive-looking path(s) | robots.txt is read by everyone, including attackers. Don't list staging or admin URLs there — block them via auth or IP allow-listing instead. The Disallow only asks polite bots to stay away; it doesn't restrict access. |
| info | No robots.txt or sitemap.xml content to analyze | No action needed. |
| info | Sitemap discovered ⟨count⟩ URLs | No action needed unless the sitemap is leaking pages you didn't intend to publish. |

## Evidence the check records

- Sitemap discovered ⟨count⟩ URLs: First 5: ⟨value⟩
- robots.txt advertises ⟨count⟩ sensitive-looking path(s): Disallow entries that look interesting: ⟨value⟩
- No robots.txt or sitemap.xml content to analyze: Neither /robots.txt nor common sitemap URLs returned usable content.

## How to verify manually

Commands to confirm the issue by hand, and again after you fix it:

```
curl -s https://example.com/robots.txt
curl -s https://example.com/sitemap.xml | head -50
curl -s https://example.com/wp-sitemap.xml | head -50
```

## Compliance mapping

- **compliance_map / pci_dss**: 12.5
- **compliance_map / nist_800_53**: CM-8
- **compliance_map / iso_27001**: A.8.1

## Run only this check

```
wpsecscan only robots_sitemap https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
