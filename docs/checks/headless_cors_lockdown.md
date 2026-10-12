---
id: headless_cors_lockdown
title: "Headless WP REST CORS lockdown (F12)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 124
---

# Headless WP REST CORS lockdown (F12)

**check_id**: `headless_cors_lockdown`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-942
**D3FEND**: D3-NTA

## What it does

F12 (v2.8.0) — Headless WordPress CORS origin lockdown.

For sites detected as headless (Next.js / Astro / Gatsby consuming
`/wp-json/`), verify that the WordPress origin's REST endpoints don't
emit a wildcard `Access-Control-Allow-Origin: *` AND that
authenticated endpoints require credentials. Wildcard CORS on the WP
origin nullifies the headless-frontend's same-origin assumption and
lets ANY website read the operator's REST data.

Companion to the existing `headless_wp_audit` check (which detects
the headless pattern); this one tests the actual CORS policy on the
WP backend.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | F12: WP REST CORS policy is over-permissive (⟨count⟩ endpoint(s)) | Set a strict CORS policy on the WP origin via Apache/nginx/Cloudflare: only allow your headless frontend's origin (e.g. `Access-Control-Allow-Origin: https://www.yoursite.com`), never wildcard, and only set `Access-Control-Allow-Credentials: true` if you actually need cross-origin authenticated requests. If WP is purely the data backend (no admin UI on the internet), block CORS entirely at the edge. |
| info | F12: WP REST CORS policy is restrictive | No action needed. |

## Evidence the check records

- F12: WP REST CORS policy is over-permissive (⟨count⟩ endpoint(s)): Probed with Origin: ⟨rogue_origin⟩ ⟨value⟩ Any website the user's browser visits can issue authenticated GETs to these endpoints.
- F12: WP REST CORS policy is restrictive: No wildcard or reflected Access-Control-Allow-Origin header detected.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.8.20

## References

- https://wpsecscan-cors-probe.invalid
- https://www.yoursite.com

## Run only this check

```
wpsecscan only headless_cors_lockdown https://example.com
```

`only` runs this check alone and prints its findings.
