---
id: wp_cron_disabled
title: "DISABLE_WP_CRON without replacement"
severity_max: info
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 123
---

# DISABLE_WP_CRON without replacement

**check_id**: `wp_cron_disabled`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1562.008 — Impair Defenses: Disable Cloud Logs

## What it does

Detect DISABLE_WP_CRON without confirmed external replacement.

If wp-cron.php returns 403/redirect-to-login rather than the empty 200
WordPress normally serves, DISABLE_WP_CRON is likely set. That's good for
performance — but ONLY if a real cron job (or a host-managed scheduler)
replaces it. Without a replacement, scheduled events (digest emails, post
publication, plugin upkeep, transient cleanup) silently stop firing.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | DISABLE_WP_CRON likely set, X-WP-Cron header confirms replacement | No action. |
| info | DISABLE_WP_CRON may be set, no confirmation of replacement scheduler | If you intentionally disabled wp-cron, confirm the replacement is running. Typical replacements: - cron: */15 * * * * curl -s https://YOURSITE/wp-cron.php?doing_wp_cron &gt; /dev/null - systemd timer or Windows Task Scheduler at the same cadence - hosts like WP Engine / Kinsta run a managed cron — check the panel If no replacement is set, scheduled events are silently broken. |

## Evidence the check records

- DISABLE_WP_CRON may be set, no confirmation of replacement scheduler: /wp-cron.php → ⟨why⟩. This suggests DISABLE_WP_CRON is true in wp-config.php. WordPress's scheduled events (digests, transients, post publication, plugin tasks) will NOT fire unless a real cron job or host-managed scheduler hits wp-cron.php periodically. We can't verify that externally.
- DISABLE_WP_CRON likely set, X-WP-Cron header confirms replacement: /wp-cron.php → ⟨why⟩. X-WP-Cron header present — replacement scheduler is active.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: CM.L2-3.4.7
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 4.8
- **compliance_v2 / iso_27001_2022**: A.8.9

## References

- https://YOURSITE/wp-cron.php?doing_wp_cron

## Run only this check

```
wpsecscan only wp_cron_disabled https://example.com
```

`only` runs this check alone and prints its findings.
