# Email header injection probe

**check_id**: `sendmail_injection`
**aggressive**: yes
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

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28

## Run only this check

```
wpsecscan --target https://example.com --only sendmail_injection
```
