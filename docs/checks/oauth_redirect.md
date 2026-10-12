---
id: oauth_redirect
title: "OAuth / login redirect-URI"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 129
---

# OAuth / login redirect-URI

**check_id**: `oauth_redirect`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1204.001 — User Execution: Malicious Link

## What it does

OAuth / login redirect-URI validation probe.

WordPress's wp-login.php and several OAuth plugins accept a `redirect_to` /
`redirect_uri` parameter and bounce the user to that URL after login. Sites
that don't restrict the destination to same-origin URLs let attackers craft
phishing links where the URL bar shows YOUR domain.

Probe: send a redirect URL that points to evil.example.com and check whether
the resulting Location header (or HTML meta refresh) points to the attacker.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Unrestricted ⟨param⟩ at ⟨path⟩ — phishing-link primitive | Validate the redirect target against an allow-list of same-origin paths. For wp-login.php specifically, the `wp_safe_redirect()` core function does this — verify the plugin owning this endpoint uses it. Reference: https://developer.wordpress.org/reference/functions/wp_safe_redirect/ |
| info | No unrestricted OAuth / login redirect found | No action. |

## Evidence the check records

- No unrestricted OAuth / login redirect found: Probed ⟨count⟩ known OAuth/login redirect params with an external URL.
- Unrestricted ⟨param⟩ at ⟨path⟩ — phishing-link primitive: GET ⟨path⟩?⟨param⟩=⟨EVIL_URL⟩ -&gt; Location: ⟨loc⟩ An attacker can craft a URL on YOUR domain that, when clicked, lands the victim on an attacker-controlled page (after a login flow that looks normal).

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SC-7
- **compliance_map / iso_27001**: A.8.20
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.17

## References

- https://developer.wordpress.org/reference/functions/wp_safe_redirect/

## Run only this check

```
wpsecscan only oauth_redirect https://example.com
```

`only` runs this check alone and prints its findings.
