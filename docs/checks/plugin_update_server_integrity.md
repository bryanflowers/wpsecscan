---
id: plugin_update_server_integrity
title: "Plugin update-server HTTPS audit (F6)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 87
---

# Plugin update-server HTTPS audit (F6)

**check_id**: `plugin_update_server_integrity`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A08:2021 — Software & Data Integrity
**MITRE ATT&CK**: T1195.002 — Compromise Software Supply Chain
**CWE**: CWE-494
**D3FEND**: D3-CRO

## What it does

F6 (v2.8.1) — Plugin update-server integrity check.

WP plugins can define a custom update server via the
`update_uri` plugin header. If that URL is HTTP (not HTTPS) or
returns an invalid TLS cert, MITM attackers can serve a malicious
update package. We probe the well-known REST plugins list and
fetch the homepage for self-hosted update markers.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | F6: ⟨count⟩ plugin(s) use HTTP update server (MITM risk) | Contact each plugin author and request an HTTPS update URL. Until fixed, set `WP_HTTP_BLOCK_EXTERNAL=true` and whitelist only your trusted update hosts via `WP_ACCESSIBLE_HOSTS`. |
| info | F6: all plugin update URIs use HTTPS | No action needed. |
| info | F6: plugin-update-integrity check skipped (REST plugins list not public) | No action needed. |

## Evidence the check records

- F6: plugin-update-integrity check skipped (REST plugins list not public): GET /wp-json/wp/v2/plugins → ⟨value⟩
- F6: all plugin update URIs use HTTPS: Inspected ⟨count⟩ plugins; none use plain HTTP for updates.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.31
- **compliance_v2 / hitrust**: 10.h
- **compliance_v2 / cmmc**: SI.L2-3.14.6
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 16.11
- **compliance_v2 / iso_27001_2022**: A.8.31

## Run only this check

```
wpsecscan only plugin_update_server_integrity https://example.com
```

`only` runs this check alone and prints its findings.
