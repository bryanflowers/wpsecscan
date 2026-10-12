---
id: wc_payment_link_replay
title: "WC pay-for-order Referrer-Policy audit (F4)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 73
---

# WC pay-for-order Referrer-Policy audit (F4)

**check_id**: `wc_payment_link_replay`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle
**CWE**: CWE-200
**D3FEND**: D3-FA

## What it does

F4 (v2.8.1) — WooCommerce pay-for-order link audit.

`?pay_for_order=true&key=wc_order_xxxx` links sometimes survive past
the order being paid AND may leak via Referer / browser-history if
served on HTTP. Defensive check: confirm /checkout/order-pay/ doesn't
emit a Referer-Policy header weaker than `strict-origin-when-cross-origin`.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F4: WC pay-for-order missing Referrer-Policy header | Add `Referrer-Policy: strict-origin-when-cross-origin` to your nginx/Apache/Cloudflare config so payment-link URLs don't leak via Referer when the customer clicks out from the receipt page. |
| low | F4: weak Referrer-Policy on pay-for-order: ⟨rp⟩ | Tighten to `strict-origin-when-cross-origin` or `no-referrer`. |
| info | F4: WC pay-for-order Referrer-Policy is reasonable (⟨rp⟩) | No action needed. |

## Evidence the check records

- F4: WC pay-for-order Referrer-Policy is reasonable (⟨rp⟩): Referrer-Policy: ⟨rp⟩
- F4: WC pay-for-order missing Referrer-Policy header: GET /checkout/order-pay/ → HTTP ⟨value⟩; no Referrer-Policy set.
- F4: weak Referrer-Policy on pay-for-order: ⟨rp⟩: Referrer-Policy: ⟨rp⟩

## Compliance mapping

- **compliance_map / pci_dss**: 4.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.24
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan only wc_payment_link_replay https://example.com
```

`only` runs this check alone and prints its findings.
