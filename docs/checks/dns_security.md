# DNS security (SPF/DMARC/DKIM)

**check_id**: `dns_security`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1566.001 — Phishing: Spearphishing Attachment

## What it does

DNS-level security audit: SPF / DMARC / DKIM presence + strictness.

Uses the stdlib `socket` resolver via `asyncio.to_thread` so we don't pull
in `dnspython`. We send no real DNS packets through our HTTP client — these
are direct system DNS queries.

Only TXT records are inspected. For DKIM we test the common 'default' selector
(only confidence indicator, not authoritative — proper DKIM verification needs
the publishing selector, which we can't enumerate from outside).

## Compliance mapping

- **compliance_map / pci_dss**: 12.3
- **compliance_map / nist_800_53**: SC-20
- **compliance_map / iso_27001**: A.5.7
- **compliance_extra / hipaa**: 164.312(e)(1)
- **compliance_extra / soc2**: CC6.7
- **compliance_extra / fedramp**: SC-8
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.f
- **compliance_v2 / cmmc**: SC.L2-3.13.1
- **compliance_v2 / nist_csf**: PR.IR-01
- **compliance_v2 / cis_v8**: 4.9
- **compliance_v2 / iso_27001_2022**: A.8.20

## Run only this check

```
wpsecscan --target https://example.com --only dns_security
```
