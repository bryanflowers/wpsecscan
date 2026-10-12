---
id: stripe_webhook_audit
title: "Stripe / WooPayments webhook signature audit (A11)"
severity_max: critical
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 161
---

# Stripe / WooPayments webhook signature audit (A11)

**check_id**: `stripe_webhook_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: critical
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1565.001 — Stored Data Manipulation
**CWE**: CWE-345
**D3FEND**: D3-MA

## What it does

A11 (v2.6.0) — Stripe / WooPayments webhook endpoint audit.

WordPress payment plugins register webhook endpoints that Stripe POSTs
to on charge events. Two attack patterns:

  • The webhook endpoint accepts unsigned events (signature header
    absent or not validated) — attacker can POST forged
    `charge.succeeded` events to mark fake orders as paid.
  • The endpoint trusts the Stripe-Signature header but doesn't pin
    the secret to the LIVE secret (test-mode signatures from a
    matching test endpoint accept).

Passive: probe the common webhook paths + POST a minimal payload with
NO signature header. A 200 / 201 response is critical (signature not
required). A 400 with "missing signature" is the expected hardened
response.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | Stripe webhook endpoint accepts unsigned event: ⟨path⟩ | 1. IMMEDIATE: disable the webhook in Stripe dashboard until signature verification is fixed. 2. In the plugin's webhook handler, call `Webhook::constructEvent($payload, $sig_header, $endpoint_secret)` and reject anything that throws SignatureVerificationException. 3. Update the plugin to its latest version; many had CVEs around webhook signature validation in 2024-2025. |
| info | Stripe webhook endpoint properly requires signature: ⟨path⟩ | Endpoint is correctly auth-gated. Periodically rotate the webhook secret via Stripe dashboard + WP plugin Settings. |

## Evidence the check records

- Stripe webhook endpoint accepts unsigned event: ⟨path⟩: POST ⟨path⟩ with no Stripe-Signature header → HTTP ⟨status⟩. Body: ⟨body⟩ An unsigned-event-accepting webhook lets anyone POST `charge.succeeded` events to mark fake orders as paid.
- Stripe webhook endpoint properly requires signature: ⟨path⟩: POST ⟨path⟩ (no sig) → HTTP ⟨status⟩; body mentions signature.

## Compliance mapping

- **compliance_map / pci_dss**: 10.5.2
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.26

## Run only this check

```
wpsecscan only stripe_webhook_audit https://example.com
```

`only` runs this check alone and prints its findings.
