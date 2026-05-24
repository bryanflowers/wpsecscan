# GDPR Data-Subject-Request audit

**check_id**: `gdpr_dsr`
**aggressive**: no
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592.001 — Gather Victim Host Information: Hardware

## What it does

GDPR Data-Subject-Request (DSR) disclosure audit.

Probes common privacy-page URLs and looks for evidence the site advertises a
DSR / "right of access" / contact-the-DPO process. Under GDPR Art. 12-15, EU
sites MUST tell visitors how to exercise data rights — and many WP sites
quietly miss this.

Purely defensive: GET-only, no auth, no parameters.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: PT-2
- **compliance_map / iso_27001**: A.5.34
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: MP.L1-3.8.3
- **compliance_v2 / nist_csf**: GV.OC-04
- **compliance_v2 / cis_v8**: 3.1
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan --target https://example.com --only gdpr_dsr
```
