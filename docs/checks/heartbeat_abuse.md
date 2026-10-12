---
id: heartbeat_abuse
title: "Heartbeat API DoS surface (#7)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 66
---

# Heartbeat API DoS surface (#7)

**check_id**: `heartbeat_abuse`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499 — Endpoint Denial of Service
**CWE**: CWE-400
**D3FEND**: D3-IVA

## What it does

#7 WordPress Heartbeat API abuse / DoS probe.

`/wp-admin/admin-ajax.php?action=heartbeat` is the autosave heartbeat
endpoint. On many WP setups it accepts unauthenticated POSTs with arbitrary
`data[]` keys and does substantial DB work per request. An attacker can
hammer it to drive load.

## Request footprint

The module contains 1 request call(s) to the target (REQUEST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/info | ⟨title⟩ | Install the 'Heartbeat Control' plugin OR add: `add_action('init', function(){ if (!is_user_logged_in()) wp_deregister_script('heartbeat'); });`. Belt-and-braces: rate-limit `/wp-admin/admin-ajax.php` at the WAF level. |
| info | Heartbeat probe unreachable | No action. |

## Evidence the check records

- ⟨title⟩: 3 unauth POSTs returned status ⟨statuses⟩, avg ⟨avg_ms⟩ ms. Attackers can amplify this with a tight loop.
- Heartbeat probe unreachable: No response.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.16

## Run only this check

```
wpsecscan only heartbeat_abuse https://example.com
```

`only` runs this check alone and prints its findings.
