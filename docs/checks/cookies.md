# Cookie hardening

**check_id**: `cookies`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1539 — Steal Web Session Cookie

## What it does

Cookie hardening check — inspect Set-Cookie flags on common WP endpoints.

Looks specifically at /wp-login.php and /wp-admin/ (which set wp-* cookies on
login attempts) for missing Secure / HttpOnly / SameSite flags.

## Compliance mapping

- **compliance_map / pci_dss**: 4.2.1
- **compliance_map / nist_800_53**: SC-23
- **compliance_map / iso_27001**: A.8.20
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
wpsecscan --target https://example.com --only cookies
```
