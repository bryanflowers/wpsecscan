# Deep TLS audit

**check_id**: `tls_deep`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

Deeper TLS audit beyond the basic version-and-expiry that tls_headers does.

Checks negotiated cipher strength, presence of forward-secrecy, certificate
chain length / self-signed indicators, and SAN list (subjectAltName).

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-8
- **compliance_map / iso_27001**: A.8.20
- **compliance_extra / hipaa**: 164.312(e)(2)(i)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-13
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.10
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only tls_deep
```
