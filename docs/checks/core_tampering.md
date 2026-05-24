# Core file tampering check

**check_id**: `core_tampering`
**aggressive**: yes
**OWASP**: A08:2021 — Software & Data Integrity Failures
**MITRE ATT&CK**: T1505.003 — Server Software Component: Web Shell

## What it does

Core file tampering / backdoor heuristic check.

Probes for files that should not exist in a stock WordPress install. Hits
on these paths are signs of either a broken plugin, an attacker-planted
webshell, or a forgotten admin script.

This is heuristic — false positives are possible for unusual themes that
legitimately put .php under /wp-content/uploads/. Reported severity tiers
the response so the user can quickly triage.

## Compliance mapping

- **compliance_map / pci_dss**: 11.5.2
- **compliance_map / nist_800_53**: SI-7
- **compliance_map / iso_27001**: A.8.12
- **compliance_v2 / hitrust**: 10.j
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.DS-06
- **compliance_v2 / cis_v8**: 11.5
- **compliance_v2 / iso_27001_2022**: A.8.32

## Run only this check

```
wpsecscan --target https://example.com --only core_tampering
```
