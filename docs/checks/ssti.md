# Server-side template injection probe

**check_id**: `ssti`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-1336
**D3FEND**: D3-IVA

## What it does

Server-Side Template Injection probe.

Sends a few computational expressions in template-engine syntax to discovered
query parameters. If the response reflects the EVALUATED result (e.g. `49` for
`{{7*7}}`), the parameter is being passed unsanitized into a templating system.

Covers Jinja2/Twig (`{{...}}`), ERB/Underscore (`<%= ... %>`), Tornado
(`{% ... %}`), Velocity/JSP/EL (`${...}`), Mako (`${...}`), Java EL spring
(`#{...}`), JSF (`#{...}`), Twig math (`{{ 7*7 }}`).

Aggressive-only.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only ssti
```
