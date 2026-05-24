# SQL injection probes

**check_id**: `sqli`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Boolean / error / time-based SQL injection probes on common WP parameters.

Read-only payloads only — no DROP, INSERT, UPDATE, or destructive operators.
Detection is via:
  - SQL error fingerprints in response body
  - Differential response length between truthy ('1=1') vs falsy ('1=2') payloads
  - Time delta between baseline and SLEEP() payload (time-based blind)

Payloads are passed as raw strings via httpx `params=` so the HTTP client handles
percent-encoding once and correctly. (An earlier version pre-encoded payloads, which
httpx then percent-encoded again, corrupting the SQL fragment server-side.)

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only sqli
```
