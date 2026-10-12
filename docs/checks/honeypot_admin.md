---
id: honeypot_admin
title: "Honeypot / anti-spam detection (#19)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 90
---

# Honeypot / anti-spam detection (#19)

**check_id**: `honeypot_admin`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: info
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1078 — Valid Accounts
**CWE**: CWE-778
**D3FEND**: D3-DA

## What it does

Round-60 #19 — honeypot mode (passive intelligence-gathering check).

Detects if the target site already deploys a fake-admin honeypot (e.g.
the `wp-honeypot` plugin, or a manually-placed `/wp-admin-login.php`
that logs attackers). Doesn't deploy one — that's the user's choice and
requires write access.

If the user wants WPSecScan itself to deploy a honeypot, they install
the companion plugin which exposes a 1-click "Enable login honeypot"
admin action (see wp-plugin/wpsecscan-companion).

## Request footprint

The module contains 2 request call(s) to the target (GET x1, HEAD x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Honeypot / anti-spam detected (⟨value⟩) | Confirm the honeypot logs attacker IPs. Tail those logs into fail2ban / Cloudflare WAF block list. |
| info | No honeypot / anti-spam detected | Consider deploying a login honeypot (a fake /wp-admin-login.php that logs the attacker IP). Plugins: 'WP Honeypot' (community) or install the WPSecScan companion plugin and tick 'Enable login honeypot'. |

## Evidence the check records

- Honeypot / anti-spam detected (⟨value⟩): Paths: ⟨value⟩
- No honeypot / anti-spam detected: None of the common honeypot/anti-spam paths or plugins detected.

## Compliance mapping

- **compliance_map / pci_dss**: 10.1
- **compliance_map / nist_800_53**: AU-2
- **compliance_map / iso_27001**: A.5.7
- **compliance_extra / hipaa**: 164.312(b)
- **compliance_extra / soc2**: CC7.3
- **compliance_extra / fedramp**: AU-6
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 09.aa
- **compliance_v2 / cmmc**: AU.L2-3.3.1
- **compliance_v2 / nist_csf**: DE.CM-01
- **compliance_v2 / cis_v8**: 8.1
- **compliance_v2 / iso_27001_2022**: A.8.15

## Run only this check

```
wpsecscan only honeypot_admin https://example.com
```

`only` runs this check alone and prints its findings.
