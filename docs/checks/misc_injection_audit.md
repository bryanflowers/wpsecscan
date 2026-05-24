# LDAP/XPath/SSI/ESI/CRLF/email-header (#32-34)

**check_id**: `misc_injection_audit`
**aggressive**: yes
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-74
**D3FEND**: D3-IVA

## What it does

#32 + #33 + #34 — misc injection class probes.

#32 LDAP / XPATH / SSI / ESI injection — sends specific payloads against
    common parameters; flags any 500/error / unexpected reflection.
#33 HTTP response splitting — `\r\n` in cookie/redirect values.
#34 Email-header injection deep — From/Reply-To/Bcc/multi-line bodies.

All aggressive-only.

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
wpsecscan --target https://example.com --only misc_injection_audit
```
