---
id: yaml_workflows
title: "YAML workflow chaining (#11)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "DNS, email & infra"
words: 76
---

# YAML workflow chaining (#11)

**check_id**: `yaml_workflows`
**aggressive**: no
**category**: DNS, email & infra
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-693
**D3FEND**: D3-IVA

## What it does

#11 — YAML workflow runner check.

Runs every workflow in `~/.wpsecscan/workflows/`. See wpsecscan/workflow.py
for the schema. Workflows let templates chain — an entry template's match
gates the execution of subsequent templates filtered by tag/id.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | No YAML workflows found | No action. |
| info | YAML workflows skipped (PyYAML not installed) | No action. |
| info | YAML workflows — ⟨count⟩ workflow(s) ran, no matches | No action. |

## Evidence the check records

- YAML workflows skipped (PyYAML not installed): Install pyyaml + drop workflows in ~/.wpsecscan/workflows/ to enable.
- No YAML workflows found: Drop workflow.yaml files in ~/.wpsecscan/workflows/ to enable chained template runs.
- YAML workflows — ⟨count⟩ workflow(s) ran, no matches: Workflows: ⟨value⟩

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
wpsecscan only yaml_workflows https://example.com
```

`only` runs this check alone and prints its findings.
