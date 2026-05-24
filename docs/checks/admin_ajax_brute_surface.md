# admin-ajax throttle probe

**check_id**: `admin_ajax_brute_surface`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.001 — Brute Force

## What it does

admin-ajax brute-force surface check.

NOT a brute-force tool. We just probe whether `/wp-admin/admin-ajax.php`
applies rate-limiting to authenticated-only actions when called without
auth. We send 5 deliberately-wrong calls to a known authenticated action
(`wp-link-ajax`) and confirm:
  - That the endpoint responds (good)
  - That repeated calls don't get throttled (concerning — would let
    attackers brute-force authentication signals via this endpoint)

This complements login_throttle; admin-ajax is often forgotten.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only admin_ajax_brute_surface
```
