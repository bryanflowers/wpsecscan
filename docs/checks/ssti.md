---
id: ssti
title: "Server-side template injection probe"
severity_max: critical
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 168
---

# Server-side template injection probe

**check_id**: `ssti`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: critical
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

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| critical | SSTI confirmed at ⟨path⟩?⟨name⟩= (⟨engine⟩ family) | Audit the plugin handling this parameter. NEVER pass user input directly into `Twig::render`, `Smarty::fetch`, etc. Use the templating engine's data-binding API (pass user input as a variable, not as part of the template string). |
| info | No SSTI detected (⟨count⟩ params × ⟨count⟩ payloads tested) | No action. |
| info | SSTI probe skipped (requires --aggressive) | No action. |
| info | SSTI probe skipped — no candidate query parameters found | No action. |

## Evidence the check records

- SSTI probe skipped (requires --aggressive): This sends `{{7777*7}}` style template-syntax payloads to discovered params.
- SSTI probe skipped — no candidate query parameters found: No URL params discovered on probed pages.
- No SSTI detected (⟨count⟩ params × ⟨count⟩ payloads tested): Canary `⟨canary_prefix⟩` — no template engine evaluated our expression.
- SSTI confirmed at ⟨path⟩?⟨name⟩= (⟨engine⟩ family): Sent: ?⟨name⟩=⟨payload⟩ Response contained the evaluated result (54439) without the raw payload. Suspect template engine: ⟨engine⟩ SSTI in WordPress is rare in core but happens in plugins that use Twig/Smarty for email templates or page builders. From SSTI to RCE is usually one Jinja2-style `{{cycler.__init__.__globals__.os.popen('id').read()}}` jump.

## Compliance mapping

- **compliance_map / pci_dss**: 6.2.4
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_v2 / hitrust**: 10.m
- **compliance_v2 / cmmc**: SI.L2-3.14.7
- **compliance_v2 / nist_csf**: PR.PS-05
- **compliance_v2 / cis_v8**: 16.10
- **compliance_v2 / iso_27001_2022**: A.8.28

## References

- primary: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
- deep dive: https://portswigger.net/web-security/server-side-template-injection

## Run only this check

```
wpsecscan only ssti https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
