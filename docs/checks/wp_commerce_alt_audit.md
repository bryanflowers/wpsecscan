# Alt-commerce + booking-plugin audit (#6+8)

**check_id**: `wp_commerce_alt_audit`
**aggressive**: no
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
wpsecscan --target https://example.com --only wp_commerce_alt_audit
```
