---
id: webhooks
title: "Webhook endpoint discovery"
severity_max: info
severity_dynamic: true
aggressive: false
category: "GraphQL & APIs"
words: 64
---

# Webhook endpoint discovery

**check_id**: `webhooks`
**aggressive**: no
**category**: GraphQL & APIs
**max severity**: info (some findings take their severity at run time)
**OWASP**: A10:2021 — Server-Side Request Forgery
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Webhook endpoint discovery.

Many WP plugins register webhook receivers under `/wp-json/<plugin>/v1/webhook`
or `/?wc-api=<plugin>` and many forget to validate signatures or restrict
sources. This check discovers them and probes for the auth requirement.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | No webhook endpoints discovered | No action needed. |
| info | Webhook surface: ⟨count⟩ endpoint(s) found (⟨count⟩ auth-gated, ⟨count⟩ open) | Webhook endpoints should verify signatures from the sender (Stripe-Signature, X-WC-Webhook-Signature, etc.). Audit each plugin's webhook handler — most have a documented secret/signature check that operators sometimes leave blank. |
| varies | Open webhook endpoint: ⟨value⟩ at ⟨value⟩ | Audit the ⟨value⟩ webhook handler. Look for `verify_signature()` or equivalent. Most webhook plugins ship with a 'webhook secret' field that must be configured. |

## Evidence the check records

- No webhook endpoints discovered: Probed ⟨count⟩ known webhook paths; none responded as endpoints.
- Open webhook endpoint: ⟨value⟩ at ⟨value⟩: GET ⟨value⟩ -&gt; 200, ⟨count⟩ bytes Plugin: ⟨value⟩ body preview: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan only webhooks https://example.com
```

`only` runs this check alone and prints its findings.
