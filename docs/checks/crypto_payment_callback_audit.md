---
id: crypto_payment_callback_audit
title: "Crypto-payment webhook auth audit (#73)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "GraphQL & APIs"
words: 96
---

# Crypto-payment webhook auth audit (#73)

**check_id**: `crypto_payment_callback_audit`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: critical
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1565.003 — Runtime Data Manipulation
**CWE**: CWE-345
**D3FEND**: D3-MFA

## What it does

Crypto-payment webhook callback audit.

Round-64 #73 — WooCommerce-Crypto + similar plugins receive payment-
confirmation webhooks at /wp-json/&lt;plugin&gt;/v1/callback or
/?wc-api=&lt;plugin&gt;. Without HMAC or signature verification, an attacker
can spoof a "payment confirmed" callback and mark unpaid orders as paid.
This check probes a handful of known endpoints with a crafted callback,
flagging any that respond 200 without challenge.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Crypto-payment callback accepts unauthenticated POST: ⟨path⟩ | Add HMAC-SHA256 signature verification on the callback. The crypto-payment provider should sign the body with a shared secret you configure once. Without this, an attacker can mark any order paid by POSTing a fake callback. |
| high | Crypto-payment callback returned 'ok' for spoof: ⟨path⟩ | Verify the gateway requires a signature header. If not, switch to a gateway that does (Coinbase Commerce, BTCPay all support HMAC). |

## Evidence the check records

- Crypto-payment callback accepts unauthenticated POST: ⟨path⟩: POST ⟨path⟩ returned 200 to a spoof callback. Body (first 200): ⟨value⟩
- Crypto-payment callback returned 'ok' for spoof: ⟨path⟩: POST ⟨path⟩ -&gt; ⟨value⟩ Body starts with 'ok' — likely no auth

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: SC-13
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only crypto_payment_callback_audit https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
