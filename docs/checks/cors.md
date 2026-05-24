# CORS misconfiguration

**check_id**: `cors`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

CORS misconfiguration check.

Send Origin: evil header on a few endpoints and check whether the server
reflects it into Access-Control-Allow-Origin, especially in combination
with Access-Control-Allow-Credentials: true.

The dangerous combo: ACAO reflects attacker origin + ACAC=true → any
malicious page can read authenticated responses from the WP site.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-4
- **compliance_map / iso_27001**: A.8.21

## Run only this check

```
wpsecscan --target https://example.com --only cors
```
