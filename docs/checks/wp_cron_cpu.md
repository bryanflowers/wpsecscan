---
id: wp_cron_cpu
title: "wp-cron.php response-time amplification"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 134
---

# wp-cron.php response-time amplification

**check_id**: `wp_cron_cpu`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1499.002 — Endpoint DoS: Service Exhaustion

## What it does

wp-cron.php per-request CPU/wall-time measurement.

Existing `wp_cron_dos.py` flags wp-cron exposure. This adds a concrete
amplification arithmetic: time two sequential GETs to wp-cron.php and
compute response time. If wp-cron consistently takes &gt; 2s, a low-rate
DoS becomes very cheap (20 req/s saturates a 1-vCPU host).

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium | wp-cron.php is slow: ~⟨avg_ms⟩ ms/request — cheap DoS amplification | 1. Set `define('DISABLE_WP_CRON', true);` in wp-config.php and register a real cron (or systemd timer / host-managed scheduler) that calls /wp-cron.php?doing_wp_cron once every 5-15 minutes. 2. Block direct /wp-cron.php access from the public internet — e.g. nginx `location = /wp-cron.php { deny all; allow 127.0.0.1; }` 3. Audit which plugin is making wp-cron slow — usually a sync remote API call from a daily/hourly hook. |
| info | wp-cron.php responds in ~⟨avg_ms⟩ ms — within tolerance | No action. |

## Evidence the check records

- wp-cron.php is slow: ~⟨avg_ms⟩ ms/request — cheap DoS amplification: Two cold requests to /wp-cron.php averaged ⟨avg_ms⟩ ms. Each wp-cron hit triggers every scheduled task synchronously, so visitor-driven scheduling (without DISABLE_WP_CRON) makes the site share its compute budget with random external pingers. Concrete attack math: at ⟨avg_ms⟩ ms per request, an attacker sending ~⟨sat_rps⟩ req/s to /wp-cron.php saturates a 1-vCPU host with no auth required and no payload — just hitting a public URL repeatedly.
- wp-cron.php responds in ~⟨avg_ms⟩ ms — within tolerance: Avg of 2 cold requests: ⟨avg_ms⟩ ms.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-5
- **compliance_map / iso_27001**: A.8.6
- **compliance_v2 / hitrust**: 09.k
- **compliance_v2 / cmmc**: SC.L2-3.13.4
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 12.1
- **compliance_v2 / iso_27001_2022**: A.8.6

## Run only this check

```
wpsecscan only wp_cron_cpu https://example.com
```

`only` runs this check alone and prints its findings.
