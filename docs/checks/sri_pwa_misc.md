---
id: sri_pwa_misc
title: "SameSite/WebDAV/PWA/HTTP3/contrast (#B25+B30+B32-B34)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 127
---

# SameSite/WebDAV/PWA/HTTP3/contrast (#B25+B30+B32-B34)

**check_id**: `sri_pwa_misc`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

Round-62 bundle — small one-off checks that don't warrant their own file:

#B25 — cookie SameSite=None enforcement
#B30 — WebDAV LOCK/UNLOCK
#B32 — PWA manifest + Service Worker scope audit
#B33 — HTTP/3 + QUIC presence
#B34 — colour-contrast measurement (best-effort sample of the home CSS)

## Request footprint

The module contains 4 request call(s) to the target (GET x3, REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | SameSite=None cookie(s) missing Secure flag (⟨count⟩) | `SameSite=None` REQUIRES `Secure`. Without it, modern browsers (Chrome 80+) ignore the cookie entirely AND log a console warning. Set both flags or switch to `SameSite=Lax`. |
| medium | Service Worker registered with relative path (scope ambiguity) | Register with an absolute path + explicit scope option to avoid SW hijacking on subpaths. |
| medium | WebDAV methods advertised in OPTIONS | WebDAV is rarely needed on a public WP. Disable in nginx/Apache config (`Dav Off` in Apache, or strip the `dav_methods` directive in nginx). |
| low | PWA manifest missing start_url | Add `start_url` to ensure PWA launch behaviour is deterministic. |
| info | Colour palette analyzed (⟨count⟩ unique colours) | WCAG 2.2 requires 4.5:1 for normal text, 3:1 for large text. Use a browser-based contrast checker for accurate measurement. |
| info | HTTP/3 (QUIC) advertised via Alt-Svc | No action — HTTP/3 is good. Confirm fallback to HTTP/2 if QUIC is blocked. |
| info | PWA / Service Worker detected | PWAs persistently cache assets. Audit SW for cache-poisoning + ensure unregister-on-uninstall path. |
| info | SRI/PWA misc — clean | No action. |
| info | SRI/PWA misc — no response | No action. |

## Evidence the check records

- HTTP/3 (QUIC) advertised via Alt-Svc: alt-svc: ⟨value⟩
- Colour palette analyzed (⟨count⟩ unique colours): For full WCAG AA / AAA contrast measurement, run an in-browser tool (Lighthouse, axe-core, WAVE). This check only counts the palette: ⟨value⟩
- SameSite=None cookie(s) missing Secure flag (⟨count⟩): Cookies: ⟨value⟩
- WebDAV methods advertised in OPTIONS: Allow: ⟨value⟩ DAV: ⟨value⟩
- Service Worker registered with relative path (scope ambiguity): navigator.serviceWorker.register('⟨sw_url⟩') — scope unclear.
- PWA manifest missing start_url: Manifest at ⟨manifest_url⟩ has no start_url field.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: SI-10
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan only sri_pwa_misc https://example.com
```

`only` runs this check alone and prints its findings.
