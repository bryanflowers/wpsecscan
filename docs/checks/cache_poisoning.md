# Web-cache poisoning probe

**check_id**: `cache_poisoning`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Web-cache poisoning probe.

Sends requests with attacker-controlled headers (X-Forwarded-Host,
X-Original-URL, X-Rewrite-URL) and looks for the value being reflected in
the response. If the response is cacheable (Cache-Control: public, Age
header growing), the attacker's value can be served to other visitors.

Defensive probe only — we never poison anything; we just confirm whether
the headers ARE reflected.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.16
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SC.L2-3.13.8
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only cache_poisoning
```
