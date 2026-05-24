# HaveIBeenPwned lookup

**check_id**: `hibp`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1589.001 — Gather Victim Identity: Credentials

## What it does

HaveIBeenPwned username breach lookup.

Consumes ctx['shared']['users'] (populated by checks/users.py).
Without --hibp-token: emits info findings with HIBP URLs the user can check manually.
With --hibp-token: queries the breachedaccount API and reports breaches found.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.5
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only hibp
```
