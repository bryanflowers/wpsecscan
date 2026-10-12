---
id: webhook_signing_secrets
title: "Payment-webhook signing-secret leak"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "Other"
words: 109
---

# Payment-webhook signing-secret leak

**check_id**: `webhook_signing_secrets`
**aggressive**: no
**category**: Other
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A07:2021 — Identification & Authentication Failures
**MITRE ATT&CK**: T1552.001 — Unsecured Credentials: Files

## What it does

Detect leaked payment-webhook signing secrets in page/JS source.

Stripe, PayPal, Square use webhook-signing secrets distinct from their
public API keys. A leaked signing secret lets an attacker forge webhook
events (e.g. "order.paid") and trigger order-state changes without a
real payment. Critical — these are NOT covered by the generic
sk_live_/pk_live_ patterns in secret_leak.py.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical) | ⟨name⟩ exposed in page source | 1. ROTATE the webhook signing secret IMMEDIATELY at the provider dashboard (Stripe Dashboard → Developers → Webhooks → Signing secret → Roll). 2. Move the secret out of front-end JS / page source. It belongs in server-side environment variables only. 3. Audit webhook delivery logs at the provider for any events that hit your endpoint during the exposure window — look for events that didn't match a real customer action. |

## Evidence the check records

- ⟨name⟩ exposed in page source: Discovered at: ⟨path⟩ Value (redacted): ⟨value⟩***⟨value⟩ (⟨count⟩ chars) Webhook signing secrets are NOT public API keys — leaking one lets attackers forge webhook events. For Stripe, that means fake `payment_intent.succeeded` events; for PayPal, fake IPN callbacks; for Square, fake `payment.created` notifications. Your back-end will trust these because the HMAC verifies.

## Compliance mapping

- **compliance_map / pci_dss**: 3.7.6
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.25
- **compliance_v2 / hitrust**: 01.q
- **compliance_v2 / cmmc**: IA.L2-3.5.10
- **compliance_v2 / nist_csf**: PR.AC-01
- **compliance_v2 / cis_v8**: 6.2
- **compliance_v2 / iso_27001_2022**: A.8.25

## Run only this check

```
wpsecscan only webhook_signing_secrets https://example.com
```

`only` runs this check alone and prints its findings.
