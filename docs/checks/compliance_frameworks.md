# Compliance framework mapping — HITRUST/CMMC/NIST CSF/CIS/ISO (#63-67)

**check_id**: `compliance_frameworks`
**aggressive**: no
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
wpsecscan --target https://example.com --only compliance_frameworks
```
