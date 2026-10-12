---
id: pwa_service_worker_cache
title: "PWA service-worker precaches admin URLs (A18)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 111
---

# PWA service-worker precaches admin URLs (A18)

**check_id**: `pwa_service_worker_cache`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1005 — Data from Local System
**CWE**: CWE-200
**D3FEND**: D3-FA

## What it does

A18 (v2.6.0) — PWA service-worker cache exposure.

PWA plugins (Super-Progressive-Web-Apps, Simple-PWA, PWA for WP)
register a service worker whose `precache` list is fetched on install.
When the precache list includes `/wp-admin/` paths or admin-only assets,
those URLs become cached for any visitor who installs the PWA — they
end up in the browser's offline cache.

Passive: GET `/sw.js` + `/service-worker.js` and scan the response for
admin URL prefixes.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | PWA service worker precaches admin URLs: ⟨path⟩ | 1. Open the PWA plugin Settings and remove /wp-admin/ from the precache list. 2. In the SW's `precacheAndRoute(...)` call, exclude any URL matching /^\/wp-admin\//. 3. Tell users to clear site data once after the fix. |

## Evidence the check records

- PWA service worker precaches admin URLs: ⟨path⟩: GET ⟨path⟩ returns a SW that precaches /wp-admin/ paths. Sample: ⟨value⟩ When any visitor installs the PWA, their browser caches these admin URLs — content visible to the install user leaks into the offline cache.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only pwa_service_worker_cache https://example.com
```

`only` runs this check alone and prints its findings.
