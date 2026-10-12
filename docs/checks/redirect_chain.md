---
id: redirect_chain
title: "Redirect chain analysis"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 135
---

# Redirect chain analysis

**check_id**: `redirect_chain`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1071.001 — Application Layer Protocol: Web Protocols

## What it does

Redirect-chain analysis.

Follows redirects from / and /wp-admin/ up to 8 hops, recording every Location.
Flags:
  - Chains that bounce off-domain (potential session-cookie leak / XSS via Location)
  - Chains with HTTP→HTTPS→HTTP downgrades (mixed-content / cookie leak)
  - Excessive redirect count (&gt;5 hops on the homepage = misconfigured)

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Redirect chain from ⟨start⟩ downgrades HTTPS → HTTP | Force HTTPS everywhere. In wp-config: `define('FORCE_SSL_ADMIN', true);` At the server: a permanent 301 from http://* to https://* on all paths. |
| medium | Redirect chain from ⟨start⟩ jumps off-domain | Audit your redirect pipeline. WP shouldn't ever Location: an external host on /wp-admin/. If this is a custom plugin doing it, use wp_safe_redirect() instead. |
| low | Redirect chain from ⟨start⟩ is ⟨count⟩ hops long | Consolidate redirects. Check WP Settings → General for siteurl/home matching. |
| info | Redirect chains look clean | No action needed. |

## Evidence the check records

- Redirect chains look clean: No off-domain hops, no HTTPS→HTTP downgrades, no excessive chain length from /, /wp-admin/.
- Redirect chain from ⟨start⟩ jumps off-domain: Trace: ⟨value⟩ An attacker controlling the off-domain step can read referrer + Set-Cookie if the original cookies lacked SameSite.
- Redirect chain from ⟨start⟩ downgrades HTTPS → HTTP: Trace: ⟨value⟩ Any cookie or auth token gets sent over plaintext after the downgrade.
- Redirect chain from ⟨start⟩ is ⟨count⟩ hops long: Trace: ⟨value⟩ Long chains slow page loads and can mask misconfigs.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20

## Run only this check

```
wpsecscan only redirect_chain https://example.com
```

`only` runs this check alone and prints its findings.
