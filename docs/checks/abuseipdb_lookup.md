---
id: abuseipdb_lookup
title: "AbuseIPDB reputation (opt-in)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 102
---

# AbuseIPDB reputation (opt-in)

**check_id**: `abuseipdb_lookup`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1590.005 — Gather Victim Network: IP Addresses
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

AbuseIPDB reputation lookup.

Opt-in via --abuseipdb-token (free tier: 1000 queries/day). Resolves the target
host's IP and queries https://api.abuseipdb.com/api/v2/check for reputation
score + recent abuse reports. Flags scores &gt;= 25 as low/medium (depending),
&gt;= 75 as high — these often indicate compromised shared hosting.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/medium/low/info | ⟨title⟩ | — |
| info | AbuseIPDB lookup skipped (no token) | No action. |
| info | AbuseIPDB lookup skipped — DNS resolution failed for ⟨host⟩ | No action. |
| info | AbuseIPDB lookup skipped — couldn't extract host | No action. |
| info | AbuseIPDB query failed for ⟨ip⟩ | No action. |

## Evidence the check records

- AbuseIPDB lookup skipped (no token): Pass --abuseipdb-token TOKEN to enable IP-reputation checks. Free tier: 1000 queries/day at https://www.abuseipdb.com/account/api.
- AbuseIPDB lookup skipped — couldn't extract host: target: ⟨value⟩
- AbuseIPDB lookup skipped — DNS resolution failed for ⟨host⟩: No A record returned.
- AbuseIPDB query failed for ⟨ip⟩: Empty / non-200 response. Check token validity + daily quota.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SI-4
- **compliance_map / iso_27001**: A.8.7
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: SI.L2-3.14.3
- **compliance_v2 / nist_csf**: DE.CM-01
- **compliance_v2 / cis_v8**: 13.1
- **compliance_v2 / iso_27001_2022**: A.5.7

## References

- https://api.abuseipdb.com/api/v2/check
- https://api.abuseipdb.com/api/v2/check?
- https://www.abuseipdb.com/check/
- https://www.abuseipdb.com/account/api

## Run only this check

```
wpsecscan only abuseipdb_lookup https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
