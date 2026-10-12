---
id: wp_cli_http_exposure
title: "WP-CLI-over-HTTP endpoint exposure (A7)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 161
---

# WP-CLI-over-HTTP endpoint exposure (A7)

**check_id**: `wp_cli_http_exposure`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-78
**D3FEND**: D3-EAL

## What it does

A7 (v2.6.0) — WP-CLI-over-HTTP endpoint exposure.

Several managed-WP hosts (Pantheon, WP Engine SSH gateway, Kinsta,
Cloudways, Local-by-Flywheel "Live Link") expose a WP-CLI-shaped HTTP
endpoint so the operator can run CLI commands without SSH. These
endpoints accept a serialised command and authenticate via either:

  • A static path-segment token (`/wp-cli/{token}/cmd`).
  • A POST body field (`/wp-cli-server` with `token=...`).
  • Basic Auth on the path (`/wp-admin/maintenance/wp-cli`).

When the endpoint is reachable without auth (mis-configured custom
plugin, leftover dev tool), the host has an interactive shell. We
probe the common paths defensively and surface a critical finding
on any 200 response. No payload submission — pure existence probe.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | WP-CLI-over-HTTP endpoint reachable: ⟨path⟩ | 1. IMMEDIATE: block ⟨path⟩ at the WAF until verified. 2. Determine which plugin / mu-plugin registered the endpoint (`grep -r "⟨value⟩" wp-content/`). 3. Require auth on the endpoint: either Basic Auth at the web-server level, IP allow-list, or a one-time bearer token rotated daily. 4. Audit web-server access logs for prior unauthorised hits. |
| low | WP-CLI-over-HTTP endpoint present (auth required): ⟨path⟩ | Endpoint correctly auth-gated. Periodically audit: - that the token isn't a static long-lived value - that IP allow-list is current - that the auth check happens BEFORE command parsing |

## Evidence the check records

- WP-CLI-over-HTTP endpoint reachable: ⟨path⟩: GET ⟨path⟩ → HTTP 200, response body contains WP-CLI keyword. Excerpt: ⟨body⟩ If this endpoint accepts unauthenticated POSTs with a command body, an attacker has a remote shell on the WordPress install (equivalent to wp-config.php access).
- WP-CLI-over-HTTP endpoint present (auth required): ⟨path⟩: GET ⟨path⟩ → HTTP ⟨value⟩ (auth gate present).

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3

## Run only this check

```
wpsecscan only wp_cli_http_exposure https://example.com
```

`only` runs this check alone and prints its findings.
