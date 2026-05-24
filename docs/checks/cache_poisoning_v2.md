# Cache poisoning chain v2 (#35)

**check_id**: `cache_poisoning_v2`
**aggressive**: yes
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-444
**D3FEND**: D3-NTA

## What it does

#35 cache poisoning chain v2 — full poison-then-victim chain.

Sends two requests:
  1. Poison: GET / with X-Forwarded-Host: evil.example.com (asks cache to
     store a response whose internal links point at evil.example.com)
  2. Victim: GET / with a normal Host header — if the response contains
     evil.example.com, the cache served the poisoned copy.

Aggressive only.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.2
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only cache_poisoning_v2
```
