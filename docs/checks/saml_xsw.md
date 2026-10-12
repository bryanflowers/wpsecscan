---
id: saml_xsw
title: "SAML / XSW endpoint discovery"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 159
---

# SAML / XSW endpoint discovery

**check_id**: `saml_xsw`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
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

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | SAML SSO endpoint(s) detected — XSW testing recommended | 1. Confirm your SAML library is current (python3-saml 1.16+, simplesamlphp 2.0+, Shibboleth SP 3.2+). 2. Verify the SP rejects responses where the signature covers a different element than the asserted claims. 3. Manual test: SAMLRaider in Burp Suite has automated XSW payload generation; run it against your IdP test flow. |
| info | No SAML SSO endpoints reachable | No action. |

## Evidence the check records

- SAML SSO endpoint(s) detected — XSW testing recommended: Reachable SAML endpoints: ⟨value⟩ SAML Service Providers have a long history of XSW (XML Signature Wrapping) bugs where the SP validates ONE assertion's signature but processes a DIFFERENT, unsigned assertion's claims. wpsecscan's passive check identifies the SAML endpoint; XSW exploitation requires interactive testing with tools like SAMLRaider (Burp extension) or python3-saml's vulnerability checklist.
- No SAML SSO endpoints reachable: Probed ⟨count⟩ common SAML paths; none indicated a SAML-Service-Provider implementation.

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

- primary: https://research.aurainfosec.io/pentest/the-malicious-use-of-iam-credentials/
- deep dive: https://book.hacktricks.xyz/pentesting-web/saml-attacks/xml-signature-wrap-attacks-xsw

## Run only this check

```
wpsecscan only saml_xsw https://example.com
```

`only` runs this check alone and prints its findings.
