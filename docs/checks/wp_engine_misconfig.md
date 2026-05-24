# WP Engine private-path leaks

**check_id**: `wp_engine_misconfig`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

WP Engine-specific misconfiguration probes.

WP Engine (the host) blocks dozens of common paths via their `wpe_common_blocked_paths`
rule — but their own private paths (/wpe_common.php, /_wpeprivate/, /wp-config.txt) are
occasionally reachable on misconfigured sites.

Only runs against sites that fingerprint as WP Engine (X-Powered-By: WP Engine
or Server: nginx-wpengine).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: CM-7
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only wp_engine_misconfig
```
