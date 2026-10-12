---
id: multisite_network_option_idor
title: "Multisite network-option IDOR probe (F11)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Other"
words: 64
---

# Multisite network-option IDOR probe (F11)

**check_id**: `multisite_network_option_idor`
**aggressive**: no
**category**: Other
**max severity**: medium
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-NTA

## What it does

F11 (v2.8.1) — Multisite network-option IDOR probe.

WordPress Multisite exposes `/wp-json/wp/v2/settings` per-site,
but some plugin-extended endpoints (e.g. WP Ultimo) expose
network-level settings under a per-site path that should require
super-admin. We probe two well-known surfaces.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F11: ⟨path⟩ returns 200 unauthenticated | Verify this endpoint requires `manage_network` capability. If using WP Ultimo, update to &gt;= 2.3. |
| info | F11: multisite not detected via REST API (skipping IDOR probe) | No action needed. |

## Evidence the check records

- F11: multisite not detected via REST API (skipping IDOR probe): No multisite namespace in /wp-json/ root.
- F11: ⟨path⟩ returns 200 unauthenticated: GET ⟨path⟩ → 200 (⟨count⟩ bytes)

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
wpsecscan only multisite_network_option_idor https://example.com
```

`only` runs this check alone and prints its findings.
