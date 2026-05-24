# YAML workflow chaining (#11)

**check_id**: `yaml_workflows`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-693
**D3FEND**: D3-IVA

## What it does

#11 — YAML workflow runner check.

Runs every workflow in `~/.wpsecscan/workflows/`. See wpsecscan/workflow.py
for the schema. Workflows let templates chain — an entry template's match
gates the execution of subsequent templates filtered by tag/id.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 06.f
- **compliance_v2 / cmmc**: CA.L2-3.12.2
- **compliance_v2 / nist_csf**: ID.RA-01
- **compliance_v2 / cis_v8**: 7.5
- **compliance_v2 / iso_27001_2022**: A.5.36

## Run only this check

```
wpsecscan --target https://example.com --only yaml_workflows
```
