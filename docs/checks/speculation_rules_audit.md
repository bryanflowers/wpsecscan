---
id: speculation_rules_audit
title: "WP 6.8 Speculation Rules audit (O141)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 88
---

# WP 6.8 Speculation Rules audit (O141)

**check_id**: `speculation_rules_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1499 — Endpoint Denial of Service
**CWE**: CWE-400
**D3FEND**: D3-NTA

## What it does

O141 (v2.6.0) — Speculation Rules audit.

WP 6.8 includes the official Speculation-Rules API support: pages
emit `<script type="speculationrules">` declaring which URLs the
browser should prerender/prefetch. Misconfigured rules expose:

  • Admin-only URLs (wp-admin/...) being prerendered for anonymous
    visitors → server-side render cost + potential XSRF surface.
  • External URLs in the prerender list → CSP / network-policy leak.
  • Too-aggressive `eagerness: immediate` causing crawl-loops.

Passive: extract every speculationrules script + parse JSON; flag
medium per problematic rule found.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Speculation Rules expose problematic URLs (⟨count⟩ issue(s)) | 1. Remove admin URLs from prerender/prefetch lists. 2. Restrict cross-origin URLs to a verified allow-list. 3. Switch 'immediate' → 'moderate' or 'conservative' on public pages to avoid crawl-loop / bandwidth abuse. |

## Evidence the check records

- Speculation Rules expose problematic URLs (⟨count⟩ issue(s)): Speculation-rules issues: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6

## Run only this check

```
wpsecscan only speculation_rules_audit https://example.com
```

`only` runs this check alone and prints its findings.
