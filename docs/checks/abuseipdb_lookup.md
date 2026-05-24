# AbuseIPDB reputation (opt-in)

**check_id**: `abuseipdb_lookup`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1590.005 — Gather Victim Network: IP Addresses
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

AbuseIPDB reputation lookup.

Opt-in via --abuseipdb-token (free tier: 1000 queries/day). Resolves the target
host's IP and queries https://api.abuseipdb.com/api/v2/check for reputation
score + recent abuse reports. Flags scores >= 25 as low/medium (depending),
>= 75 as high — these often indicate compromised shared hosting.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SI-4
- **compliance_map / iso_27001**: A.8.7
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: SI.L2-3.14.3
- **compliance_v2 / nist_csf**: DE.CM-01
- **compliance_v2 / cis_v8**: 13.1
- **compliance_v2 / iso_27001_2022**: A.5.7

## Run only this check

```
wpsecscan --target https://example.com --only abuseipdb_lookup
```
