---
id: admin_ajax_brute_surface
title: "admin-ajax throttle probe"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Discovery & enumeration"
words: 146
---

# admin-ajax throttle probe

**check_id**: `admin_ajax_brute_surface`
**aggressive**: no
**category**: Discovery & enumeration
**max severity**: low
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

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low | admin-ajax.php applies no per-request throttle (⟨ATTEMPTS⟩ identical responses) | If you use a security plugin (Wordfence, Limit Login Attempts), verify its rate-limit covers /wp-admin/admin-ajax.php as well as /wp-login.php. Many configure only the latter. |
| info | admin-ajax.php applies throttling (good) | No action needed. |
| info | admin-ajax.php not reachable — skip throttle probe | No action needed. |
| info | admin-ajax.php throttle test inconclusive | No action needed. |

## Evidence the check records

- admin-ajax.php not reachable — skip throttle probe: No response from /wp-admin/admin-ajax.php.
- admin-ajax.php applies no per-request throttle (⟨ATTEMPTS⟩ identical responses): 5 calls to /wp-admin/admin-ajax.php?action=wp-link-ajax returned HTTP ⟨value⟩ every time. Many WP brute-force amplification attacks target admin-ajax actions rather than wp-login. If your login rate-limiter only covers wp-login.php, admin-ajax may be a back door.
- admin-ajax.php applies throttling (good): 5 calls returned varied statuses: ⟨statuses⟩, one or more was 429/503.
- admin-ajax.php throttle test inconclusive: Statuses across ⟨ATTEMPTS⟩ probes: ⟨statuses⟩

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan only admin_ajax_brute_surface https://example.com
```

`only` runs this check alone and prints its findings.
