---
id: payment_gateway_test_keys
title: "Payment-gateway test/sandbox key leak (#76)"
severity_max: critical
severity_dynamic: true
aggressive: false
category: "File & directory exposure"
words: 92
---

# Payment-gateway test/sandbox key leak (#76)

**check_id**: `payment_gateway_test_keys`
**aggressive**: no
**category**: File & directory exposure
**max severity**: critical (some findings take their severity at run time)
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1552.001 — Credentials In Files
**CWE**: CWE-798
**D3FEND**: D3-FCR

## What it does

Payment-gateway test/sandbox key leak in production JS.

Round-64 #76 — Stripe, PayPal, Braintree all have distinct "test" /
"sandbox" key prefixes. If a production site ships JS that uses a test
key, then (a) all card capture goes to the test environment (lost
revenue + customer support headache) AND (b) the key is now publicly
known. The opposite — a live key embedded client-side — is even worse
but a different check; this one targets the more common dev-&gt;prod
deploy bug.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| varies (critical, high, medium) | ⟨name⟩ embedded in ⟨path⟩ | If this is a TEST key on production: payments are being captured in the test environment instead of live. Action: switch the gateway plugin to its 'live' mode + regenerate keys from the gateway dashboard. If this is a LIVE SECRET key (sk_live_) client-side: ROTATE IMMEDIATELY — the key is now public. Action: gateway dashboard → revoke + reissue. Secret keys must NEVER be in HTML/JS. / Verify the test key is intentional on this environment. Production sites should use live keys, not test. |

## Evidence the check records

- ⟨name⟩ embedded in ⟨path⟩: Pattern matched at ⟨path⟩ Masked: ⟨masked⟩

## Compliance mapping

- **compliance_map / pci_dss**: 3.5.1
- **compliance_map / nist_800_53**: SC-12
- **compliance_map / iso_27001**: A.8.24

## Run only this check

```
wpsecscan only payment_gateway_test_keys https://example.com
```

`only` runs this check alone and prints its findings.
