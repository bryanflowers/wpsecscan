# Race-condition probe (parallel POSTs)

**check_id**: `race_condition`
**aggressive**: yes
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499 — Endpoint Denial of Service
**CWE**: CWE-362
**D3FEND**: D3-IVA

## What it does

Race-condition probe (aggressive).

Fires N parallel POSTs to a discovered AJAX endpoint, looks for indicators
of double-spend / accept-twice (response count > 1 success, identical idempotency
token used multiple times, etc).

Targets:
  - /wp-admin/admin-ajax.php with discovered actions
  - WooCommerce coupon-apply if WC is detected
  - Any plugin form endpoint that has a `_nonce` (we test with the SAME nonce
    in parallel to see if the server detects replay)

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only race_condition
```
