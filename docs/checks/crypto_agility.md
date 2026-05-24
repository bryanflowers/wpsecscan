# Crypto agility — PQ/TLS 1.3 hybrid/cert inventory (#47-51)

**check_id**: `crypto_agility`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-326
**D3FEND**: D3-CH

## What it does

Round-59 #47-51 — Crypto agility audit.

#47 Post-quantum cipher — does the server advertise any hybrid PQ
   key-exchange (X25519MLKEM768 / X25519Kyber768Draft00) in TLS?
#48 Hybrid TLS 1.3 — confirm TLS 1.3 with hybrid KEX
#49 Crypto inventory — list cert SAN, public-key algorithm + size, sig
   algorithm, OCSP-must-staple flag
#50 RSA key size — flag <2048 bit RSA certs (still common on old hosts)
#51 Curve preference — server advertises which ECDH curves?

All best-effort via stdlib `ssl` + optional `cryptography` parse. We
avoid pulling in heavy deps.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-13
- **compliance_map / iso_27001**: A.8.24
- **compliance_extra / hipaa**: 164.312(e)(2)(ii)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-13
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: SC.L2-3.13.11
- **compliance_v2 / nist_csf**: PR.DS-02
- **compliance_v2 / cis_v8**: 3.11
- **compliance_v2 / iso_27001_2022**: A.8.24

## Run only this check

```
wpsecscan --target https://example.com --only crypto_agility
```
