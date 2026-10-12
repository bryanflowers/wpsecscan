---
id: oauth_redirect_misconfig
title: "OAuth redirect_uri staging/localhost misconfig"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 117
---

# OAuth redirect_uri staging/localhost misconfig

**check_id**: `oauth_redirect_misconfig`
**aggressive**: no
**category**: Authentication & session
**max severity**: medium
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1566.002 — Phishing: Spearphishing Link

## What it does

OAuth misconfig: extract client_id + redirect_uri from Google/Facebook/Apple
login flows discovered on the site and flag staging/localhost redirect URIs.

When oauth_oidc detects a Sign-in-with-Google button etc., this check pulls
the redirect_uri parameter from the discovered authorisation URL and looks
for staging/localhost markers. Production OAuth apps with non-production
redirects can accept tokens for any redirect (depending on provider) — a
phishing-prep vector.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | ⟨provider⟩ OAuth redirect_uri points at staging/localhost host | 1. Verify the OAuth app at the ⟨provider⟩ developer console and confirm the registered redirect URI list contains ONLY production URLs. 2. If staging/localhost was needed during testing, register a separate OAuth app for staging and use different client_id values per environment. 3. Audit recent OAuth callbacks for hits against the staging URI — those are users who may have been redirected away from your real domain mid-authentication. |

## Evidence the check records

- ⟨provider⟩ OAuth redirect_uri points at staging/localhost host: OAuth flow on homepage uses: client_id: ⟨client_id⟩ redirect_uri: ⟨uri⟩ A production OAuth flow with a staging/localhost redirect_uri indicates either a misconfigured OAuth app (accepting tokens for non-production destinations) or a copy-paste error that shipped to production. Either way, fix it before someone uses it as a phishing prep.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.3
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.10
- **compliance_v2 / hitrust**: 10.k
- **compliance_v2 / cmmc**: CM.L2-3.4.7
- **compliance_v2 / nist_csf**: PR.IP-12
- **compliance_v2 / cis_v8**: 4.8
- **compliance_v2 / iso_27001_2022**: A.5.10

## Run only this check

```
wpsecscan only oauth_redirect_misconfig https://example.com
```

`only` runs this check alone and prints its findings.
