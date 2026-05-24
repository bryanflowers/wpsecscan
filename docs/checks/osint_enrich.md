# OSINT — ASN/geo/bug-bounty/cert TX (#36-43)

**check_id**: `osint_enrich`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#36-43 — OSINT enrichment check.

Wraps wpsecscan/integrations/osint.py — resolves target IP, looks up ASN +
geo, checks for active bug-bounty programme, lists recent cert issuances.
All best-effort, all info-level.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SI-4
- **compliance_map / iso_27001**: A.8.7
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: SI.L2-3.14.3
- **compliance_v2 / nist_csf**: ID.RA-02
- **compliance_v2 / cis_v8**: 13.1
- **compliance_v2 / iso_27001_2022**: A.5.7

## Run only this check

```
wpsecscan --target https://example.com --only osint_enrich
```
