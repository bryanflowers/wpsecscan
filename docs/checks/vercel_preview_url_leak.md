---
id: vercel_preview_url_leak
title: "Vercel / Netlify preview-URL leak (A16)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 121
---

# Vercel / Netlify preview-URL leak (A16)

**check_id**: `vercel_preview_url_leak`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-IAA

## What it does

A16 (v2.6.0) — Vercel / Netlify / GH-Pages preview-URL leak.

Headless WP setups deploy the frontend to Vercel/Netlify/GH-Pages and
publish preview URLs per branch. Those preview hosts often:

  • Skip the production WAF.
  • Skip authentication that the prod CDN enforces.
  • Expose draft posts / unpublished previews.

This check scrapes robots.txt, sitemap.xml, and the homepage HTML for
preview-URL patterns and flags any reference to a `*.vercel.app`,
`*.netlify.app`, `*.pages.dev`, `*.github.io`, `*.fly.dev`,
`*.surge.sh` host that isn't on the same apex as the target.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Frontend preview-URL hosts referenced: ⟨count⟩ foreign hosts | 1. For each host, confirm whether it should be public. 2. If not, enable Vercel/Netlify password-protection on the preview deployment. 3. Add a `<meta name='robots' content='noindex'>` to staging templates so the URLs don't appear in search results. 4. Audit your sitemap-generator: it should NOT include the staging origin in robots.txt or sitemap.xml. |

## Evidence the check records

- Frontend preview-URL hosts referenced: ⟨count⟩ foreign hosts: Preview / staging hosts referenced from sitemap or HTML: ⟨value⟩ These hosts likely bypass your production WAF and may serve unpublished drafts / staging content that wasn't intended to be public.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan only vercel_preview_url_leak https://example.com
```

`only` runs this check alone and prints its findings.
