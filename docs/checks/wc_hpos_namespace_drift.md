---
id: wc_hpos_namespace_drift
title: "WC HPOS namespace-drift advisory (F68)"
severity_max: low
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 181
---

# WC HPOS namespace-drift advisory (F68)

**check_id**: `wc_hpos_namespace_drift`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: low
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-863
**D3FEND**: D3-IAA

## What it does

F68 (v2.8.3) — WooCommerce HPOS namespace-drift advisory.

WC 9.0+ ships High-Performance Order Storage (HPOS), which moves
orders from posts/postmeta tables to dedicated wc_orders tables.
When HPOS is active, `/wp-json/wc/v3/orders` can return data from a
different DB table than the admin UI shows, and per-order permission
checks must be applied in BOTH code paths. Misconfigured custom
plugins frequently authorize one but not the other.

We detect HPOS via the `/wp-json/wc-admin/features` endpoint and emit
an advisory when active so the operator audits any custom order-
modifying plugin code for dual-path permission checks.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | F68: WC HPOS active — audit custom order code for dual-path permission checks | Run WC's built-in `wp wc hpos verify_orders` (CLI) to confirm the legacy and HPOS tables are consistent. Audit custom plugins for direct `$wpdb->prefix . 'posts'` queries against the `shop_order` post type — these silently bypass HPOS data. |
| info | F68: WC HPOS not active | No action needed. |
| info | F68: wc-admin features endpoint unreachable; HPOS state unknown | No action needed if WC isn't installed. |

## Evidence the check records

- F68: WC HPOS not active: HPOS flag not set in wc-admin features.
- F68: wc-admin features endpoint unreachable; HPOS state unknown: GET /wp-json/wc-admin/features → ⟨value⟩
- F68: WC HPOS active — audit custom order code for dual-path permission checks: WC reports HPOS (High-Performance Order Storage) is enabled. Orders are stored in wc_orders tables (not posts/postmeta). Any custom plugin that touches orders must apply permission checks via both `wc_get_order()` AND the legacy `get_post()` paths — a common bug class authorizes one but not the other, exposing orders via the unaudited path.

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.2
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_v2 / hitrust**: 01.v
- **compliance_v2 / cmmc**: AC.L1-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 6.8
- **compliance_v2 / iso_27001_2022**: A.8.3

## Run only this check

```
wpsecscan only wc_hpos_namespace_drift https://example.com
```

`only` runs this check alone and prints its findings.
