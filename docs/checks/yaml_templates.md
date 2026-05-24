# YAML templates (nuclei-style) (#9)

**check_id**: `yaml_templates`
**aggressive**: no
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-693
**D3FEND**: D3-IVA

## What it does

#9 — YAML template runner check.

Discovers and runs every `*.yaml` / `*.yml` template in
`~/.wpsecscan/templates/`. Templates use a subset of nuclei's grammar
(see wpsecscan/template_engine.py for the supported schema).

Optional dep: PyYAML. If not installed, the check emits an info finding
explaining how to enable.

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
wpsecscan --target https://example.com --only yaml_templates
```
