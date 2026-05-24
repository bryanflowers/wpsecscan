# REST permission_callback audit (#3)

**check_id**: `rest_permission_audit`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-862
**D3FEND**: D3-RAC

## What it does

#3 WP REST `permission_callback` audit.

Fetches /wp-json/ + every namespace's route listing, then probes each
route with GET (no auth). Flags routes that respond 200 (open) when
their `methods` list includes POST/PUT/DELETE (privileged actions
usually need auth). Many plugins omit `permission_callback` or use
`return true` — those routes leak data + accept writes.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.3
- **compliance_extra / hipaa**: 164.312(a)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L2-3.1.5
- **compliance_v2 / nist_csf**: PR.AA-05
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.5.15

## Run only this check

```
wpsecscan --target https://example.com --only rest_permission_audit
```
