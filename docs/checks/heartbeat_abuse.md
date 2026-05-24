# Heartbeat API DoS surface (#7)

**check_id**: `heartbeat_abuse`
**aggressive**: no
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.16

## Run only this check

```
wpsecscan --target https://example.com --only heartbeat_abuse
```
