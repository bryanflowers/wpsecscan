---
id: osint_enrich
title: "OSINT — ASN/geo/bug-bounty/cert TX (#36-43)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 60
---

# OSINT — ASN/geo/bug-bounty/cert TX (#36-43)

**check_id**: `osint_enrich`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

#36-43 — OSINT enrichment check.

Wraps wpsecscan/integrations/osint.py — resolves target IP, looks up ASN +
geo, checks for active bug-bounty programme, lists recent cert issuances.
All best-effort, all info-level.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium/info | Cert-transparency: ⟨count⟩ cert(s) issued for *.⟨host⟩ in the last 7d | If any cert name is unexpected, suspect domain hijacking / certificate-issuance fraud. Verify against your CA dashboard. |
| info | Bug-bounty programme found on ⟨value⟩ | If you intend to test for bounties, read the programme's scope + rules first. |
| info | OSINT enrich skipped (no host) | No action. |
| info | OSINT enrichment — no notable signals | No action. |
| info | OSINT: ⟨ip⟩ — ⟨value⟩ | No action. |

## Evidence the check records

- OSINT enrich skipped (no host): Couldn't parse host.
- Bug-bounty programme found on ⟨value⟩: Programme page: ⟨value⟩
- OSINT enrichment — no notable signals: ASN/geo/bug-bounty/cert-history queries returned nothing of note.

## Compliance mapping

- **compliance_map / pci_dss**: 1.4
- **compliance_map / nist_800_53**: SI-4
- **compliance_map / iso_27001**: A.8.7
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: SI.L2-3.14.3
- **compliance_v2 / nist_csf**: ID.RA-02
- **compliance_v2 / cis_v8**: 13.1
- **compliance_v2 / iso_27001_2022**: A.5.7

## References

- https://crt.sh/?q=%25

## Run only this check

```
wpsecscan only osint_enrich https://example.com
```

`only` runs this check alone and prints its findings.
