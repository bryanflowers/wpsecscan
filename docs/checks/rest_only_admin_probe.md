---
id: rest_only_admin_probe
title: "REST-only headless /wp-admin lockdown (F15)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 80
---

# REST-only headless /wp-admin lockdown (F15)

**check_id**: `rest_only_admin_probe`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-284
**D3FEND**: D3-NTA

## What it does

F15 (v2.8.1) — REST-only admin / wp-admin lockdown probe.

Best practice for headless WP installs: block /wp-admin from the
public internet entirely; admins SSH-tunnel or VPN. We flag if
/wp-admin/ is reachable AND the site exposes any signal it's a
REST-only install (no theme renders on /, JSON API works).

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F15: REST-only / headless site has public /wp-admin | Block /wp-admin and /wp-login.php at nginx/Cloudflare: location ~ ^/wp-(admin\|login\.php) { allow VPN_IPS; deny all; } REST API stays public for headless front-end consumption. |

## Evidence the check records

- F15: REST-only / headless site has public /wp-admin: REST API reachable, homepage shows headless markers, yet /wp-admin/ is publicly accessible. Reduces attack-surface mitigation that headless was supposed to offer.

## Compliance mapping

- **compliance_map / pci_dss**: 1.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 01.o
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.AC-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan only rest_only_admin_probe https://example.com
```

`only` runs this check alone and prints its findings.
