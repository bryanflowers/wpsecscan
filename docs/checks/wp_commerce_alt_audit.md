---
id: wp_commerce_alt_audit
title: "Alt-commerce + booking-plugin audit (#6+8)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 108
---

# Alt-commerce + booking-plugin audit (#6+8)

**check_id**: `wp_commerce_alt_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-639
**D3FEND**: D3-RAC

## What it does

Round-59 #6 + #8 — Alternative e-commerce + booking plugin audit.

#6 Easy Digital Downloads, WP eCommerce, WP-Simple-Pay, MarketPress.
   Non-Woo carts that the main WooCommerce check misses.
#8 Booking: Bookly, Amelia, BookingPress, MotoPress Booking, WP Simple Booking.
   IDOR on /bookings/{id} is the canonical bug; we detect the plugin then
   probe the listing endpoint anonymously.

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨name⟩: anonymous bookings listing reachable | Lock `⟨rest_path⟩` to `manage_options` or per-user ownership. Booking listings disclose customer PII (name/email/phone). |
| medium | ⟨name⟩ REST endpoint readable unauthenticated | Restrict `⟨rest_path⟩` to logged-in customers (`is_user_logged_in()` + capability). |
| info | Alt-commerce plugin: ⟨name⟩ ⟨value⟩ detected | Non-Woo carts often miss core hardening (nonces on `add_to_cart`, capability on `delete_order`). |
| info | Alt-commerce/booking audit — no plugins detected | No action. |
| info | Booking plugin: ⟨name⟩ ⟨value⟩ detected | Booking plugins frequently expose IDOR on `/bookings/{id}` and `/customers/{id}`. Audit each REST/AJAX action. |

## Evidence the check records

- Alt-commerce plugin: ⟨name⟩ ⟨value⟩ detected: ⟨plugin_path⟩ reachable.
- Booking plugin: ⟨name⟩ ⟨value⟩ detected: ⟨plugin_path⟩ reachable.
- Alt-commerce/booking audit — no plugins detected: Probed 5 commerce + 5 booking plugins.
- ⟨name⟩ REST endpoint readable unauthenticated: GET ⟨rest_path⟩ -&gt; ⟨value⟩ (⟨count⟩ bytes).
- ⟨name⟩: anonymous bookings listing reachable: GET ⟨rest_path⟩ -&gt; ⟨value⟩ (⟨count⟩ bytes).

## Compliance mapping

- **compliance_map / pci_dss**: 7.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.15
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only wp_commerce_alt_audit https://example.com
```

`only` runs this check alone and prints its findings.
