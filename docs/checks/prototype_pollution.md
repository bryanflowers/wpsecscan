# Prototype-pollution reflection probe

**check_id**: `prototype_pollution`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1059.007 — JavaScript Execution

## What it does

Prototype-pollution probe (client + server-side via JSON middleware).

Sends `?__proto__[polluted]=wpsec` and `?constructor[prototype][polluted]=wpsec`
style payloads. If the value is reflected in a response or appears in a
Set-Cookie / response header / inline JSON config, the server's JSON parsing
or merge utility is vulnerable.

Aggressive-only (sends crafted URL parameters).

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
wpsecscan --target https://example.com --only prototype_pollution
```
