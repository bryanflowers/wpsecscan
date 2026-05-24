# wp-cron.php DoS amplification (#2)

**check_id**: `wp_cron_dos`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.003 — Application Exhaustion Flood
**CWE**: CWE-400
**D3FEND**: D3-IVA

## What it does

#2 wp-cron.php DoS-amplification check.

`wp-cron.php` runs WordPress's scheduled-task system. Each web visit can
trigger it. If the site doesn't set `DISABLE_WP_CRON` + use system cron,
EVERY page-view that touches wp-cron costs the server N database queries
+ all the cron callbacks. An attacker can hit wp-cron.php in a loop.

We probe wp-cron.php directly (no DOING_CRON header) and time the response.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.16

## Run only this check

```
wpsecscan --target https://example.com --only wp_cron_dos
```
