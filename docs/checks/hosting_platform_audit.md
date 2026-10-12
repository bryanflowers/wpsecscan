---
id: hosting_platform_audit
title: "WP Engine/Kinsta/CF/Amplify audits (#16-22)"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "WordPress core, plugins & themes"
words: 164
---

# WP Engine/Kinsta/CF/Amplify audits (#16-22)

**check_id**: `hosting_platform_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592.004 — Client Configurations
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#16-22 — Cloud / hosting-platform audits in one module.

#16 WP Engine hardening (extends existing wp_engine_misconfig with 2026-vintage paths)
#17 Kinsta / Pressable / Pantheon fingerprint + known-issue checks
#18 Cloudflare API-token / R2 / Workers leak scan
#19 AWS Amplify build-config leak
#20 Heroku / Render / Fly.io free-tier WP fingerprint
#21 GitHub Pages WP-mirror detection
#22 CDN cache-key confusion probe

## Request footprint

The module contains 4 request call(s) to the target (GET x3, HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Cloudflare API token leak: ⟨value⟩... | Rotate the token at https://dash.cloudflare.com/profile/api-tokens. Audit any wp_localize_script() / inline JS that bundles secrets to the front-end. |
| varies (critical, high, medium) | Hosting platform leak: ⟨label⟩ at ⟨path⟩ | Restrict ⟨path⟩ at the web server. These platform-specific files are not meant to be web-accessible. |
| high | CDN cache may be poisonable via X-Forwarded-Host | Configure the CDN to include X-Forwarded-Host in the cache key, OR strip X-Forwarded-Host at the edge. |
| low | Free-tier PaaS reference in homepage (Heroku/Render/Fly.io) | Free-tier dynos sleep when idle. If this is production, move to a paid plan. If this is staging, ensure it's not indexed (X-Robots-Tag: noindex). |
| info | Hosting platform fingerprint: ⟨host_fp⟩ | Cross-reference ⟨host_fp⟩'s security advisories for platform-specific patches/known-issues. |
| info | Hosting/cloud audit — no platform leaks detected | No action. |

## Evidence the check records

- Hosting/cloud audit — no platform leaks detected: Probed 6 platform paths + CF token regex + cache-poisoning differential.
- Hosting platform leak: ⟨label⟩ at ⟨path⟩: HEAD ⟨path⟩ -&gt; ⟨value⟩.
- Hosting platform fingerprint: ⟨host_fp⟩: Headers reveal the hosting platform. Relevant headers: ⟨value⟩
- Cloudflare API token leak: ⟨value⟩...: A token matching the CF token format appears in the homepage HTML.
- Free-tier PaaS reference in homepage (Heroku/Render/Fly.io): The homepage HTML references a free-tier PaaS URL.
- CDN cache may be poisonable via X-Forwarded-Host: Sent two requests with different X-Forwarded-Host values; the rewritten URL from the first request appeared in the response.

## Compliance mapping

- **compliance_map / pci_dss**: 2.2
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## References

- https://dash.cloudflare.com/profile/api-tokens

## Run only this check

```
wpsecscan only hosting_platform_audit https://example.com
```

`only` runs this check alone and prints its findings.
