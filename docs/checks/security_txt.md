# security.txt (RFC 9116) audit

**check_id**: `security_txt`
**aggressive**: no
**OWASP**: A09:2021 — Logging & Monitoring Failures
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

security.txt / .well-known endpoint audit (RFC 9116).

Modern sites should publish /.well-known/security.txt with a security
contact + scope statement. Also probes for /.well-known/change-password
(RFC 8615) and /humans.txt.

## Compliance mapping

- **compliance_map / pci_dss**: 12.10.1
- **compliance_map / nist_800_53**: IR-7
- **compliance_map / iso_27001**: A.5.24
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: IR.L2-3.6.2
- **compliance_v2 / nist_csf**: RS.CO-02
- **compliance_v2 / cis_v8**: 17.2
- **compliance_v2 / iso_27001_2022**: A.5.5

## Run only this check

```
wpsecscan --target https://example.com --only security_txt
```
