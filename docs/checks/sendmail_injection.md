---
id: sendmail_injection
title: "Email header injection probe"
severity_max: high
severity_dynamic: false
aggressive: true
category: "Injection & client-side"
words: 141
---

# Email header injection probe

**check_id**: `sendmail_injection`
**aggressive**: yes
**category**: Injection & client-side
**max severity**: high
**OWASP**: A03:2021 — Injection
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application

## What it does

Sendmail header-injection probe for contact forms.

WordPress contact-form plugins occasionally use user input as the From: or
Reply-To: header without sanitization, allowing attackers to inject CC: /
BCC: headers via CRLF in the From field. We probe common form action URLs
with CRLF-encoded headers in the email field and look for signs the server
accepted the input.

Read-only: we don't actually trigger a send — we just check the immediate
response. Confirming actual injection requires checking inbound mail, which
the scanner can't do.

## Request footprint

The module contains 1 request call(s) to the target (POST x1). Calls inside loops send more than one request, so treat this as a minimum.

This is an aggressive check: it sends active probes. It only runs with --aggressive, and without --owned (or a recorded ownership consent for the host) the scanner downgrades the run to passive checks only.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Possible email header injection at ⟨value⟩ | Audit the form plugin. Modern CF7 / WPForms strip CRLF, but old custom plugins often don't. Block at the handler: filter input through wp_mail()'s sanitize_email() and strip \r\n manually. |
| info | No email header injection markers detected | No action needed for the tested endpoints (custom forms may still be vulnerable — audit each). |

## Evidence the check records

- No email header injection markers detected: Probed ⟨count⟩ common contact-form endpoints with CRLF in email field.
- Possible email header injection at ⟨value⟩: POST ⟨value⟩ with `email: wpsx-probe@example.com\r\nBcc: ...` -&gt; HTTP ⟨value⟩ ⟨value⟩ If the underlying mail handler also doesn't strip these headers, attackers can BCC themselves on every contact-form submission (extracting customer emails) or relay spam.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan only sendmail_injection https://example.com --aggressive --owned
```

`only` runs this check alone and prints its findings.
