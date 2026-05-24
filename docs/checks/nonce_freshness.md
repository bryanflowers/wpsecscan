# WP nonce freshness audit

**check_id**: `nonce_freshness`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

WP nonce freshness / rotation check.

WordPress nonces are tied to a (user, action, tick) tuple where tick is the
current 12-hour window. A fresh nonce should change every ~12 hours; a static
nonce (or one tied to nothing) is broken.

We fetch /wp-login.php twice and extract `_wpnonce` values, then a third time
after 1 second. If all three are identical, the nonce isn't tied to time and
likely isn't tied to user either — it's effectively static.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.7
- **compliance_map / nist_800_53**: AC-12
- **compliance_map / iso_27001**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only nonce_freshness
```
