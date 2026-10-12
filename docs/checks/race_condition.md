---
id: race_condition
title: "Race-condition probe (parallel POSTs)"
severity_max: medium
severity_dynamic: false
aggressive: true
category: "SSRF / RCE / open access"
words: 174
---

# Race-condition probe (parallel POSTs)

**check_id**: `race_condition`
**aggressive**: yes
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499 — Endpoint Denial of Service
**CWE**: CWE-362
**D3FEND**: D3-IVA

## What it does

Race-condition probe (aggressive).

Fires N parallel POSTs to a discovered AJAX endpoint, looks for indicators
of double-spend / accept-twice (response count &gt; 1 success, identical idempotency
token used multiple times, etc).

Targets:
  - /wp-admin/admin-ajax.php with discovered actions
  - WooCommerce coupon-apply if WC is detected
  - Any plugin form endpoint that has a `_nonce` (we test with the SAME nonce
    in parallel to see if the server detects replay)

## Request footprint

The module contains 2 request call(s) to the target (GET x1, REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | WC coupon-apply accepts ⟨ok_count⟩ parallel requests | Test against an ACTUAL valid one-use coupon — if the user gets a discount applied multiple times, the race is exploitable. Mitigation: WooCommerce 4.0+ has built-in transaction-level coupon locking; older versions don't. Upgrade or backport. |
| info | Race-condition probe completed; no anomalies | No action. |
| info | Race-condition probe skipped (requires --aggressive) | No action. |
| info | admin-ajax accepts ⟨PARALLEL_COUNT⟩ parallel requests without rate-limiting | Whether this is a problem depends on the specific action. heartbeat is harmless. Audit any plugin AJAX handler that performs CHARGES, ADDS-CREDIT, APPLIES-COUPON, or any other state-changing single-use operation — those need an idempotency check. |

## Evidence the check records

- Race-condition probe skipped (requires --aggressive): This fires 20 parallel POSTs against AJAX/coupon endpoints to test race-safety.
- admin-ajax accepts ⟨PARALLEL_COUNT⟩ parallel requests without rate-limiting: Fired ⟨PARALLEL_COUNT⟩ parallel POSTs to /wp-admin/admin-ajax.php?action=heartbeat. All ⟨n_ok⟩ returned HTTP 200. No per-request rate limit at the AJAX layer.
- Race-condition probe completed; no anomalies: Fired ⟨PARALLEL_COUNT⟩ parallel POSTs against admin-ajax + WC coupons.
- WC coupon-apply accepts ⟨ok_count⟩ parallel requests: Fired ⟨PARALLEL_COUNT⟩ parallel POSTs with the same coupon code. ⟨ok_count⟩ returned 200. WooCommerce should reject duplicate coupon applies within one session. If a real coupon is applied this way (one with usage_limit_per_user=1), the limit can be bypassed via parallel application.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://portswigger.net/web-security/race-conditions
- video: https://www.youtube.com/watch?v=tKJzsaB1ZvI

## Run only this check

```
wpsecscan only race_condition https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
