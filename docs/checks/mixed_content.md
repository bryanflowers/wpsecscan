---
id: mixed_content
title: "Mixed-content (HTTP-in-HTTPS) audit"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 68
---

# Mixed-content (HTTP-in-HTTPS) audit

**check_id**: `mixed_content`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

Mixed-content audit.

HTTPS pages that load HTTP resources (scripts, images, fonts) leak the page
contents to network attackers and break the integrity guarantee. Modern
browsers block most of these but legacy plugins/themes still emit them.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Mixed content: ⟨total_resources⟩ HTTP resource(s) loaded from ⟨count⟩ host(s) | Replace every http:// with https:// (or //) in your theme + plugins. Common sources: - Hardcoded image URLs in posts: search-and-replace via WP-CLI: `wp search-replace 'http://yourdomain' 'https://yourdomain'` - Plugin assets pinned to http:// — update the plugin or override its enqueue - 3rd-party widgets (analytics, fonts) — switch to their HTTPS endpoints - Browser tip: open DevTools → Console → look for 'Mixed Content' warnings |
| info | Mixed-content check skipped — site is HTTP, not HTTPS | Serve the site over HTTPS first; then this check becomes meaningful. |
| info | No mixed-content (HTTP) resources detected | No action needed. |

## Evidence the check records

- Mixed-content check skipped — site is HTTP, not HTTPS: The whole site is unencrypted; mixed-content is moot.
- No mixed-content (HTTP) resources detected: Scanned ⟨count⟩ pages for HTTP src=/href=/action= attributes; none found.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.20

## References

- https://yourdomain

## Run only this check

```
wpsecscan only mixed_content https://example.com
```

`only` runs this check alone and prints its findings.
