# Deep TLS protocol + cipher + cert audit

**check_id**: `tls_protocol_audit`
**aggressive**: no
**OWASP**: A02:2021 — Cryptographic Failures
**MITRE ATT&CK**: T1557 — Adversary-in-the-Middle

## What it does

Deep TLS protocol audit.

Uses the stdlib `ssl` module via `asyncio.to_thread` (no extra deps) to probe:
  1. Whether TLS 1.0 / 1.1 are still ACCEPTED (PCI-DSS bans them)
  2. Negotiated cipher suite (flag RC4 / 3DES / NULL / EXPORT)
  3. Certificate expiry distance (warn <30 days)
  4. Server name verification + SAN coverage
  5. OCSP-must-staple presence (cert extension)

The existing `tls_deep` check is shallower — this complements it.

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
wpsecscan --target https://example.com --only tls_protocol_audit
```
