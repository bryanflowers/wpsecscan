---
id: compliance_frameworks
title: "Compliance framework mapping — HITRUST/CMMC/NIST CSF/CIS/ISO (#63-67)"
severity_max: info
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 143
---

# Compliance framework mapping — HITRUST/CMMC/NIST CSF/CIS/ISO (#63-67)

**check_id**: `compliance_frameworks`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: info
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1499 — Endpoint DoS
**CWE**: CWE-693
**D3FEND**: D3-NTA

## What it does

Round-59 #63-67 — Extended compliance framework mappings as a check.

Doesn't probe the target — instead it correlates the scan's findings
against the requested framework's controls and emits one finding per
control gap. The frameworks added in this round (on top of round-58's
HIPAA/FERPA/SOC2/FedRAMP/GDPR) are:

#63 HITRUST CSF v11.4
#64 CMMC 2.0 Levels 1-3
#65 NIST CSF 2.0 (Govern + Identify + Protect + Detect + Respond + Recover)
#66 CIS Critical Controls v8 (18 controls)
#67 ISO 27001:2022 Annex A (line-by-line — 93 controls)

The mappings live in data/compliance_extra.json (round-58) +
data/compliance_v2.json (this round). The check itself only triggers
when the user passes `--compliance-framework=hitrust` (or similar) via
ctx; otherwise it is a no-op.

## Request footprint

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| info | Compliance framework: ⟨value⟩ mapping loaded | This framework's evidence is folded into the JSON report under `compliance_⟨fw⟩`. Use the executive_pack reporter for a stakeholder-friendly summary. |
| info | Compliance-framework audit — pass --compliance-framework=NAME to enable | Run again with e.g. --compliance-framework=hitrust to map findings against HITRUST CSF v11.4 controls. |

## Evidence the check records

- Compliance framework: ⟨value⟩ mapping loaded: ⟨count⟩ check_ids mapped. Review the JSON report `compliance_⟨fw⟩` section for per-control evidence.
- Compliance-framework audit — pass --compliance-framework=NAME to enable: Valid frameworks: ⟨value⟩

## Compliance mapping

- **compliance_map / pci_dss**: 12.1
- **compliance_map / nist_800_53**: PM-9
- **compliance_map / iso_27001**: A.5.31
- **compliance_extra / hipaa**: 164.308(a)(1)
- **compliance_extra / soc2**: CC3.1
- **compliance_extra / fedramp**: PM-9
- **compliance_extra / gdpr**: Article 30

## Run only this check

```
wpsecscan only compliance_frameworks https://example.com
```

`only` runs this check alone and prints its findings.
