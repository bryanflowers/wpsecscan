---
id: misc_injection_audit
title: "LDAP/XPath/SSI/ESI/CRLF/email-header (#32-34)"
severity_max: high
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 97
---

# LDAP/XPath/SSI/ESI/CRLF/email-header (#32-34)

**check_id**: `misc_injection_audit`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: high
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨label⟩ injection — response contains marker '⟨value⟩' | Sanitise ⟨param⟩ input. ⟨label⟩ requires context-specific escaping — see OWASP cheat sheets. |
| info | Misc injection probes skipped (passive) | No action. |
| info | Misc injection probes — clean (⟨count⟩ classes tested) | No action. |

## Evidence the check records

- Misc injection probes skipped (passive): Pass --aggressive.
- Misc injection probes — clean (⟨count⟩ classes tested): LDAP / XPath / SSI / ESI / CRLF / email-header markers absent from responses.
- ⟨label⟩ injection — response contains marker '⟨value⟩': GET /?⟨param⟩=⟨value⟩ marker '⟨value⟩' present in response.

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
wpsecscan only misc_injection_audit https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
