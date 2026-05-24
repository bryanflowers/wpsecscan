# Session-fixation precondition probe

**check_id**: `session_fixation`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1539 — Steal Web Session Cookie
**CWE**: CWE-384
**D3FEND**: D3-MFA

## What it does

H4 Session-fixation chain.

Pattern: an attacker sets a session cookie on the victim BEFORE login.
A vulnerable application re-uses that cookie value after authentication,
letting the attacker — who already knows the cookie — hijack the session.

We can't fully test fixation without admin credentials, but we CAN detect
the precondition: does the server accept arbitrary client-set values for
the cookies it later treats as session identifiers? If yes AND the cookies
are flagged HttpOnly+Secure+SameSite=Strict, fixation requires user-side
XSS. If NO HttpOnly / loose SameSite, fixation is trivial.

This is a derivative finding from the existing cookie check, so we keep it
narrow: pre-set a synthetic value, hit /wp-login.php, verify the server
either:
  (a) ignores our value and issues a fresh cookie (good — no fixation),
  (b) echoes our value back (bad — fixation likely possible).

## Compliance mapping

- **compliance_map / pci_dss**: 8.3
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.8.5
- **compliance_extra / hipaa**: 164.312(a)(2)(i)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-3
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 10.b
- **compliance_v2 / cmmc**: AC.L2-3.1.1
- **compliance_v2 / nist_csf**: PR.AA-01
- **compliance_v2 / cis_v8**: 5.4
- **compliance_v2 / iso_27001_2022**: A.8.5

## Run only this check

```
wpsecscan --target https://example.com --only session_fixation
```
