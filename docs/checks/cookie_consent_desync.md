---
id: cookie_consent_desync
title: "Tracking cookies fire pre-consent (A20)"
severity_max: medium
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 113
---

# Tracking cookies fire pre-consent (A20)

**check_id**: `cookie_consent_desync`
**aggressive**: no
**category**: Transport & headers
**max severity**: medium
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592 — Gather Victim Host Information
**CWE**: CWE-359
**D3FEND**: D3-FA

## What it does

A20 (v2.6.0) — IAB TCF v2.2 cookie-consent desync.

Many WP cookie-banner plugins (Cookie Notice, CookieYes, Complianz,
Iubenda) set a `cookielawinfo-checkbox-*` consent cookie when the user
accepts; the analytics cookies (`_ga`, `_fbp`, `__hssc`, `_pin_unauth`,
`_uetsid`) should only fire AFTER consent.

Passive: GET / with NO cookies, scan response Set-Cookie + inline
&lt;script&gt; tags for analytics cookies firing pre-consent. The mere
PRESENCE of `_ga` in Set-Cookie before any consent interaction is the
violation.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| medium | Tracking cookies set before consent: ⟨value⟩ | 1. Audit your cookie-banner plugin's 'block tags' or 'script blocker' feature — it should rewrite analytics &lt;script&gt; tags to type='text/plain' until consent is granted. 2. Move analytics initialization into the cookie-banner's consent callback ('onAccept'), not into the page &lt;head&gt;. |

## Evidence the check records

- Tracking cookies set before consent: ⟨value⟩: Anonymous GET / returned Set-Cookie headers for tracking cookies: ⟨value⟩. Per ePrivacy + GDPR + IAB TCF v2.2, analytics/marketing cookies MUST NOT fire until the user accepts the banner. This is a textbook ePrivacy violation.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: AC-21
- **compliance_map / iso_27001**: A.5.34

## Run only this check

```
wpsecscan only cookie_consent_desync https://example.com
```

`only` runs this check alone and prints its findings.
