---
id: wp_cron_dos
title: "wp-cron.php DoS amplification (#2)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "SSRF / RCE / open access"
words: 117
---

# wp-cron.php DoS amplification (#2)

**check_id**: `wp_cron_dos`
**aggressive**: no
**category**: SSRF / RCE / open access
**max severity**: medium
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | wp-cron.php DoS amplification — avg ⟨value⟩ ms per hit | Set `define('DISABLE_WP_CRON', true);` in wp-config.php, then schedule `php /path/wp-cron.php` via system cron (every 5min). Optionally `location = /wp-cron.php { deny all; }` once system cron handles it. |
| info | wp-cron.php responds in ~⟨value⟩ ms (no amplification observed) | No action. |
| info | wp-cron.php unreachable | No action. |

## Evidence the check records

- wp-cron.php unreachable: No response on /wp-cron.php.
- wp-cron.php DoS amplification — avg ⟨value⟩ ms per hit: 3 sample hits to /wp-cron.php averaged ⟨value⟩ ms · responses: ⟨value⟩ A loop of 100 req/s against this endpoint would consume ~⟨value⟩ CPU-seconds/s — easy to overwhelm.
- wp-cron.php responds in ~⟨value⟩ ms (no amplification observed): Sample times: ⟨value⟩ ms

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.16

## Run only this check

```
wpsecscan only wp_cron_dos https://example.com
```

`only` runs this check alone and prints its findings.
