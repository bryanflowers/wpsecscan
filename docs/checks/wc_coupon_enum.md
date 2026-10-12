---
id: wc_coupon_enum
title: "WC coupon-code enumeration oracle (F1)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 224
---

# WC coupon-code enumeration oracle (F1)

**check_id**: `wc_coupon_enum`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: medium
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.001 — Brute Force: Password Guessing
**CWE**: CWE-799
**D3FEND**: D3-NTA

## What it does

F1 (v2.8.0) — WooCommerce coupon-code enumeration probe.

Brute-force coupon discovery is a documented WC fraud pattern (Wordfence
2024 + 2025 incident write-ups). Attackers probe the WC Store API
(`/wp-json/wc/store/v1/cart/apply-coupon`) or the legacy AJAX endpoint
(`?wc-ajax=apply_coupon`) with dictionary codes; valid codes are
revealed by the response shape ("Coupon applied" vs "Coupon does not
exist"), and the operator's discount structure leaks.

This check is DEFENSIVE: we probe with 5 obviously-fake codes and
detect whether the endpoint responds in a way that distinguishes
valid-from-invalid codes (which would enable a brute-force attack).
We do NOT actually try a real dictionary — that would be offensive
and would also trigger WAF blocks.

Output: a single finding if the endpoint distinguishes outcomes, OR
an info finding noting WC was not detected on the target.

## Request footprint

The module contains 2 request call(s) to the target (GET x1, POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | F1: WC coupon-apply endpoint leaks an enumeration oracle | Add rate-limiting to /wp-json/wc/store/v1/cart/apply-coupon (Wordfence / WP Cerber / Cloudflare rate-rules all work). Consider returning a uniform response for all unknown codes (generic 'invalid' message + identical status). For high-value coupons, gate via a one-time link / authenticated session rather than a public code. |
| info | F1: WC coupon-apply endpoint returns uniform response for unknown codes | No action needed; coupon-enumeration oracle is not exposed. |
| info | F1: WooCommerce Store API not detected — coupon-enum probe skipped | No action needed; this check only applies to WooCommerce sites. |
| info | F1: coupon-apply endpoint unreachable — couldn't profile enumeration risk | Either WC is misconfigured, or the apply-coupon endpoint is rate-limited/blocked — both of which incidentally mitigate coupon enumeration. Verify the endpoint behaves as expected for real customers. |

## Evidence the check records

- F1: WooCommerce Store API not detected — coupon-enum probe skipped: GET /wp-json/wc/store/v1/ did not respond with a WC marker.
- F1: coupon-apply endpoint unreachable — couldn't profile enumeration risk: Only ⟨count⟩ of 5 probes returned a response.
- F1: WC coupon-apply endpoint leaks an enumeration oracle: 5 distinct fake codes produced ⟨count⟩ different response shapes (status, body-len): ⟨value⟩. A brute-force attacker dictionary-attacking your coupon space can detect valid codes by the response shape divergence.
- F1: WC coupon-apply endpoint returns uniform response for unknown codes: All 5 fake probes produced the same response shape: ⟨value⟩.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.8.5

## Run only this check

```
wpsecscan only wc_coupon_enum https://example.com
```

`only` runs this check alone and prints its findings.
