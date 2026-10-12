---
id: payment_commerce_deep
title: "Payment/PCI 4.0 deep audit (#58-62)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 191
---

# Payment/PCI 4.0 deep audit (#58-62)

**check_id**: `payment_commerce_deep`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-311
**D3FEND**: D3-CR

## What it does

Round-59 #58-62 — Payment / commerce deep audit.

#58 Stripe/PayPal/Square config — detect each plugin + check that
   `pk_test_` keys aren't accidentally leaking in production HTML.
#59 PCI-DSS 4.0 checklist (informational guidance per finding)
#60 PCI evidence mode — emit a JSON evidence pack alongside findings
   so QSAs can include in their workpaper.
#61 3DS2 check — does the merchant's Stripe/PayPal integration enforce
   3DS2 on EU cards? Best-effort via the JS init params.
#62 Order/refund IDOR — `/wp-admin/admin-ajax.php?action=woocommerce_get_refunded_order_items&order_id=N`
   without auth.

## Request footprint

The module contains 5 request call(s) to the target (GET x5). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Test/sandbox payment key leaked in production HTML: ⟨value⟩... | Replace the sandbox/test key with the live key. ROTATE the leaked test key in the payment-provider dashboard regardless. |
| high | WooCommerce AJAX action `⟨action⟩` reachable unauthenticated | This AJAX endpoint must check `current_user_can('edit_shop_orders')`. Patch in `class-wc-ajax.php` or upgrade WooCommerce. |
| medium | Stripe integration without 3DS2 hint in HTML | Set `request_three_d_secure: 'automatic'` on the PaymentIntent. PSD2 SCA is required on EU cards — without it, transactions are decline-eligible. |
| info | PCI evidence pack written | Attach this JSON to your SAQ workpaper. |
| info | PCI-DSS 4.0 — checklist for sites taking cards | Document SAQ-A (host fully outsourced to Stripe Elements/PayPal hosted-fields) or SAQ-A-EP. The latter requires script-integrity monitoring on the checkout page. |
| info | Payment plugin(s) detected: ⟨value⟩ | Audit each integration's webhook signature verification + 3DS2 enforcement. |
| info | Payment-commerce audit — no payment plugins detected | No action. |

## Evidence the check records

- PCI-DSS 4.0 — checklist for sites taking cards: Key 4.0 controls: 6.4.3 — script integrity on payment page (SRI) 11.6.1 — change/script-tamper detection on payment page 3.5.1.2 — disk-encryption for any cardholder backup 8.4 — MFA on all access to CDE 12.10 — IR plan, tested annually
- Payment-commerce audit — no payment plugins detected: Probed 6 popular payment plugins.
- PCI evidence pack written: Wrote ⟨ev_path⟩
- Stripe integration without 3DS2 hint in HTML: No `request_three_d_secure` / `payment_method_options` reference found in checkout HTML.
- WooCommerce AJAX action `⟨action⟩` reachable unauthenticated: GET ...?action=⟨action⟩&order_id=1 -&gt; 200, body=⟨value⟩
- Test/sandbox payment key leaked in production HTML: ⟨value⟩...: Pattern matched in front-end HTML.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.5.34
- **compliance_extra / hipaa**: 164.308(a)(8)
- **compliance_extra / soc2**: CC8.1
- **compliance_extra / fedramp**: SI-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan only payment_commerce_deep https://example.com
```

`only` runs this check alone and prints its findings.
