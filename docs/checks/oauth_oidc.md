# OAuth2 / OIDC discovery audit

**check_id**: `oauth_oidc`
**aggressive**: no
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

## Compliance mapping

- **compliance_map / pci_dss**: 8.3
- **compliance_map / nist_800_53**: IA-2
- **compliance_map / iso_27001**: A.8.5
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## Run only this check

```
wpsecscan --target https://example.com --only oauth_oidc
```
