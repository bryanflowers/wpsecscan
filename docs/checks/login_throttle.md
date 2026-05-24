# Login rate-limiting test

**check_id**: `login_throttle`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110.003 — Brute Force: Password Spraying

## What it does

Login-throttling defense test.

Sends 6 deliberately-wrong logins for a synthetic non-existent user.
If the site rate-limits / shows a captcha by attempt #6, throttling works.
If all 6 attempts return identical 'invalid credentials' pages, the site
isn't throttling.

This is NOT brute force: same wrong password each time, single fake user.
Never enumerates passwords.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.4
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17
- **compliance_extra / hipaa**: 164.312(d)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: AC-7
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.r
- **compliance_v2 / cmmc**: AC.L2-3.1.8
- **compliance_v2 / nist_csf**: PR.AA-03
- **compliance_v2 / cis_v8**: 6.2
- **compliance_v2 / iso_27001_2022**: A.8.5

## Run only this check

```
wpsecscan --target https://example.com --only login_throttle
```
