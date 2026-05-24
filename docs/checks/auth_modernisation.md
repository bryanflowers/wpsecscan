# Auth modernisation — passkey/2FA/SAML/OAuth/JWT/magic-link (#40-46)

**check_id**: `auth_modernisation`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1110 — Brute Force
**CWE**: CWE-308
**D3FEND**: D3-MFA

## What it does

Round-59 #40-46 — Auth modernisation audit.

#40 WebAuthn / passkey support — detect a passkey-capable login form
   (looks for `navigator.credentials.get` or `webauthn` strings in
   login JS).
#41 TOTP / 2FA plugin detection — Wordfence 2FA, Google Authenticator,
   Two-Factor.
#42 SAML SSO depth — `simplesamlphp`, `wp-saml-auth`, OneLogin.
#43 OAuth2 + PKCE — detect public clients that should use PKCE.
#44 Refresh-token rotation — JWT-based REST auth refresh paths.
#45 Session-cookie rotation — does the login response set a new
   `wordpress_logged_in_*` cookie value on re-login? (only a presence
   check — full rotation needs an authenticated test).
#46 Magic-link login — magic-link plugins (Passwordless, MagicLogin).

## Compliance mapping

- **compliance_map / pci_dss**: 8.4.2
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.5.17
- **compliance_extra / hipaa**: 164.312(d)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: IA-2
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 01.j
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only auth_modernisation
```
