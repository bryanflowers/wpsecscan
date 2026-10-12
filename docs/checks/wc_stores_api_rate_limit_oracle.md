---
id: wc_stores_api_rate_limit_oracle
title: "WC Stores API cart-add rate-limit probe (F67)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 139
---

# WC Stores API cart-add rate-limit probe (F67)

**check_id**: `wc_stores_api_rate_limit_oracle`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.002 — Service Exhaustion
**CWE**: CWE-770
**D3FEND**: D3-NTA

## What it does

F67 (v2.8.3) — WC 9.x Stores API cart-add rate-limit probe.

The `/wp-json/wc/store/v1/cart/add-item` endpoint in WC 9.x has no
default rate-limit. Mass-add-to-cart is a documented DoS vector
(every add creates a session row in wp_options + a DB write). We
send a 5-request burst with the same trivial payload and measure
inter-request delay; if all 5 land in &lt;1s, the endpoint is
unprotected.

Defensive — we use product_id=1 which usually 404s; we're measuring
THROTTLE, not actually adding items.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F67: WC Stores API cart-add has no rate-limit | Add a rate-limit rule at your WAF / Cloudflare / Wordfence (`/wp-json/wc/store/v1/cart/*` — limit to ~10 req/min per IP). Consider WC 9.3+ which ships built-in throttling for this endpoint. |
| info | F67: WC Store API not detected — rate-limit probe skipped | No action needed. |
| info | F67: WC Stores API cart-add appears rate-limited | No action needed. |

## Evidence the check records

- F67: WC Stores API cart-add appears rate-limited: 5 probes in ⟨value⟩ms with statuses ⟨statuses⟩.
- F67: WC Store API not detected — rate-limit probe skipped: No response from /wp-json/wc/store/v1/
- F67: WC Stores API cart-add has no rate-limit: 5 POST /wp-json/wc/store/v1/cart/add-item requests completed in ⟨value⟩ms with no 429 response. Status codes: ⟨statuses⟩. Mass-add-to-cart can DoS the wp_options table on busy stores.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 09.k
- **compliance_v2 / cmmc**: CP.L2-3.7.6
- **compliance_v2 / nist_csf**: PR.IR-04
- **compliance_v2 / cis_v8**: 11.3
- **compliance_v2 / iso_27001_2022**: A.5.30

## Run only this check

```
wpsecscan only wc_stores_api_rate_limit_oracle https://example.com
```

`only` runs this check alone and prints its findings.
