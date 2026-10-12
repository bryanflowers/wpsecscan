---
id: oauth_oidc
title: "OAuth2 / OIDC discovery audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 165
---

# OAuth2 / OIDC discovery audit

**check_id**: `oauth_oidc`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078.004 — Valid Accounts: Cloud Accounts
**CWE**: CWE-345
**D3FEND**: D3-MFA

## What it does

OAuth2 / OpenID Connect audit.

Detects common OAuth-SSO providers (Auth0, Cognito, Okta, Discord, Microsoft)
in the site's HTML / DNS / .well-known.

Tests for:
  - PKCE enforcement (challenges accepted without code_verifier?)
  - state-parameter validation (omitting it shouldn't work)
  - redirect_uri strictness (does it allow open-redirect)
  - ID-token signature validation

## Request footprint

The module contains 3 request call(s) to the target (GET x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | OAuth redirect_uri NOT strictly validated at ⟨candidate⟩ | Audit the OAuth handler. The redirect_uri MUST be validated against an allow-list registered with the client_id at OAuth-app-registration time. RFC 6749 §3.1.2.4 requires exact-string matching of the redirect URI. |
| medium | OIDC discovery doc omits PKCE support | Configure the OIDC server to require PKCE. For Auth0/Cognito/Okta this is a client-app-settings toggle. For custom implementations, see RFC 7636. |
| info | No OAuth2/OIDC providers detected | No action. |
| info | OAuth/OIDC audit skipped — no response from / | No action. |
| info | OAuth/OIDC providers detected: ⟨value⟩ | No action — informational. See follow-up findings for misconfig probes. |

## Evidence the check records

- OAuth/OIDC providers detected: ⟨value⟩: Identified from homepage HTML and well-known endpoints.
- OAuth/OIDC audit skipped — no response from /: GET / returned no body.
- No OAuth2/OIDC providers detected: Scanned homepage HTML for ⟨count⟩ provider patterns + /.well-known/openid-configuration; none matched.
- OAuth redirect_uri NOT strictly validated at ⟨candidate⟩: GET ⟨candidate⟩?redirect_uri=⟨EVIL_REDIRECT⟩ -&gt; ⟨value⟩ Location: ⟨value⟩ The endpoint accepted an off-host redirect URI without validation. An attacker can craft a phishing URL on YOUR domain that redirects to theirs.
- OIDC discovery doc omits PKCE support: /.well-known/openid-configuration is missing the `code_challenge_methods_supported` field. Modern OAuth clients should REQUIRE PKCE (S256). Servers that don't advertise it are likely accepting the legacy auth-code-without-PKCE flow, which is vulnerable to interception.

## Compliance mapping

- **compliance_map / pci_dss**: 8.3
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.8.5
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## References

- primary: https://portswigger.net/web-security/oauth
- deep dive: https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
- https://wpsec-oauth-test.example.invalid/phished

## Run only this check

```
wpsecscan only oauth_oidc https://example.com
```

`only` runs this check alone and prints its findings.
