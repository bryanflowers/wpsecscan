# Honeypot / anti-spam detection (#19)

**check_id**: `honeypot_admin`
**aggressive**: no
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
wpsecscan --target https://example.com --only honeypot_admin
```
