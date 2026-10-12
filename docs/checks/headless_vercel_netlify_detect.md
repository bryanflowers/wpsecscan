---
id: headless_vercel_netlify_detect
title: "Headless WP on Vercel/Netlify with reachable REST (N138)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 128
---

# Headless WP on Vercel/Netlify with reachable REST (N138)

**check_id**: `headless_vercel_netlify_detect`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

N138 (v2.7.0) — Headless WP on Vercel / Netlify detection.

When the WP REST API is reachable directly on a public WordPress host
but the frontend is served from Vercel/Netlify, the operator typically
forgets to either:
  (a) block direct access to wp-json/ on the WP host, or
  (b) put the WP host behind HTTP Basic Auth.

This check fingerprints the front-end deployment platform from response
headers + flags any reachable /wp-json/ on a HOST whose front-end is
Vercel/Netlify/etc.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Headless WP detected (⟨platform⟩) — REST API reachable from the public host | 1. If your headless frontend fetches from a SEPARATE WP host (e.g. wp.example.com), put that host behind HTTP Basic Auth or an IP allow-list so only your build server can reach REST. 2. If the frontend uses preview-mode draft fetching, gate that with Vercel Edge Middleware or Netlify Edge Functions checking an HMAC-signed preview token. 3. Confirm /wp-json/wp/v2/users isn't returning user enumeration. |

## Evidence the check records

- Headless WP detected (⟨platform⟩) — REST API reachable from the public host: Front-end platform fingerprint: ⟨platform⟩ (via headers: x-vercel-id=⟨x_vercel⟩, x-nf-request-id=⟨x_nf⟩, server=⟨server⟩) GET /wp-json/ returns HTTP 200 — the WordPress REST API is directly accessible. In a headless setup the WP host typically should NOT serve REST to anonymous visitors.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only headless_vercel_netlify_detect https://example.com
```

`only` runs this check alone and prints its findings.
