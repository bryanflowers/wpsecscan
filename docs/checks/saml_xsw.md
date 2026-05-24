# SAML / XSW endpoint discovery

**check_id**: `saml_xsw`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078.004 — Valid Accounts: Cloud Accounts
**CWE**: CWE-347
**D3FEND**: D3-MFA

## What it does

SAML XML Signature Wrapping (XSW) probe.

If the site exposes a SAML SSO endpoint, test a tiny XSW variant: a SAML
response with an extra wrapped assertion. A vulnerable SP processes the
unsigned assertion's claims while validating the SIGNED inner assertion —
classic SSO auth bypass.

This is a low-aggressiveness PASSIVE probe: we only LOOK for SAML endpoints
and serve known-good error responses. The actual XSW payload tests are
deferred to an active extension (out of scope for the passive check).

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
wpsecscan --target https://example.com --only saml_xsw
```
