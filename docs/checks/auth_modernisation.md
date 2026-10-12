---
id: auth_modernisation
title: "Auth modernisation — passkey/2FA/SAML/OAuth/JWT/magic-link (#40-46)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 197
---

# Auth modernisation — passkey/2FA/SAML/OAuth/JWT/magic-link (#40-46)

**check_id**: `auth_modernisation`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
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

## Request footprint

The module contains 6 request call(s) to the target (GET x6). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | No 2FA plugin detected | Install Two-Factor (core team plugin) or Wordfence 2FA. Required for admin accounts under modern compliance regimes (PCI 4.0 / SOC 2 CC6.1). |
| medium | WordPress login cookie missing hardening flags | Force secure cookies in wp-config.php: define('COOKIE_DOMAIN', '...'); and use a plugin like 'WP Cookie Setter' or filter `auth_cookie` with $secure_only=true. |
| low | JWT refresh endpoint detected: ⟨path⟩ | Ensure refresh tokens are SINGLE-USE — invalidate the old refresh-token on every successful refresh. Many JWT plugins skip this and become vulnerable to token-replay. |
| low | Magic-link plugin detected: ⟨name⟩ | Verify magic-link tokens are: (a) single-use, (b) short-lived (&lt;15min), (c) bound to the original requesting IP or User-Agent. Otherwise mailbox compromise = WordPress takeover. |
| low | No passkey / WebAuthn on /wp-login.php | Add passkey support via WP-Passkeys plugin or paid Wordfence/iThemes Premium. Passkeys are the only practical phishing-resistant 2FA. |
| info | 2FA plugin(s) installed: ⟨value⟩ | No action. |
| info | Auth modernisation audit — no auth plugins detected | No action. |
| info | OAuth2 authorisation endpoint reachable: ⟨path⟩ | If you operate a public client (mobile / SPA), require `code_challenge` (PKCE — RFC 7636) on the authorisation request. Without PKCE, the auth-code interception attack is trivial. |
| info | Passkey / WebAuthn capability detected on login | Excellent — passkeys are phishing-resistant. Confirm fallback (TOTP / WebAuthn-second-factor) is also enabled. |
| info | SAML SSO plugin detected: ⟨name⟩ | Audit the SAML response signature validation. Common bug: accepting unsigned assertions when only the SAMLResponse envelope is signed. See also the XSW check. |

## Evidence the check records

- Passkey / WebAuthn capability detected on login: Found navigator.credentials / webauthn reference in /wp-login.php JS.
- No passkey / WebAuthn on /wp-login.php: No webauthn JS reference detected.
- 2FA plugin(s) installed: ⟨value⟩: Plugin file reachable.
- No 2FA plugin detected: Probed ⟨value⟩ known 2FA plugins, none responded.
- OAuth2 authorisation endpoint reachable: ⟨path⟩: GET ⟨path⟩ -&gt; ⟨value⟩
- JWT refresh endpoint detected: ⟨path⟩: GET ⟨path⟩ -&gt; ⟨value⟩
- SAML SSO plugin detected: ⟨name⟩: ⟨path⟩ reachable.
- Magic-link plugin detected: ⟨name⟩: ⟨path⟩ reachable.
- WordPress login cookie missing hardening flags: Set-Cookie: ⟨value⟩ ; missing: ⟨value⟩

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
wpsecscan only auth_modernisation https://example.com
```

`only` runs this check alone and prints its findings.
