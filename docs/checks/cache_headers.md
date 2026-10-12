---
id: cache_headers
title: "Cache-header audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 200
---

# Cache-header audit

**check_id**: `cache_headers`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1556 — Modify Authentication Process

## What it does

Cache-header audit.

Look at response headers from a few endpoints to detect:
  - Authenticated content cached publicly (`Cache-Control: public` on logged-in views)
  - Missing `Vary` on cookie-sensitive content
  - Cache-poisoning vectors via unkeyed inputs
  - Stale-while-revalidate / immutable assets pointing at non-versioned paths

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Response is cache-control: public AND sets a cookie | Either remove the cookie from cacheable responses, or downgrade Cache-Control to private. Cookies belong on responses your origin generates per-user, not on shared cached pages. |
| medium | X-Forwarded-Host is reflected into HTML — cache-poisoning candidate | Either strip X-Forwarded-Host at the edge or add it to the cache key. In WordPress, set absolute URLs via wp_options.siteurl/home — never via the Host header at runtime. |
| low | /wp-login.php sets cookies but Vary header doesn't include Cookie | Add `Vary: Cookie` on the wp-login.php response. Nginx: `add_header Vary 'Cookie' always;` inside the login location block. |
| info | CDN reports cached response age = ⟨age⟩s | No action unless the response is supposed to be fresh (e.g., logged-in admin views). |
| info | No cache-header anomalies detected | No action needed. |

## Evidence the check records

- Response is cache-control: public AND sets a cookie: GET / response headers: Cache-Control: ⟨cc⟩ Set-Cookie: ⟨value⟩ A public-cacheable response with Set-Cookie can poison the CDN — every visitor downstream of the cache receives the same cookie. If that cookie is session-bearing, you've shared a session globally.
- /wp-login.php sets cookies but Vary header doesn't include Cookie: GET /wp-login.php response: Set-Cookie present but Vary doesn't mention Cookie. Vary: ⟨value⟩ Some CDNs may then cache the response per-URL without varying by cookies, potentially leaking auth-related cookies to other users.
- CDN reports cached response age = ⟨age⟩s: Age: ⟨age⟩, X-Cache: ⟨value⟩
- X-Forwarded-Host is reflected into HTML — cache-poisoning candidate: GET / with X-Forwarded-Host: wpsecscan-cache-probe.invalid was reflected in the response body. If the response is also cacheable and the cache doesn't key on XFH, an attacker can poison the cache with content under their domain.
- No cache-header anomalies detected: Cache-Control: ⟨value⟩ Vary: ⟨value⟩ Age: ⟨value⟩ X-Cache: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.7
- **compliance_map / nist_800_53**: AC-12
- **compliance_map / iso_27001**: A.8.21

## Run only this check

```
wpsecscan only cache_headers https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
