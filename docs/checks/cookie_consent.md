---
id: cookie_consent
title: "GDPR/ePrivacy cookie-consent audit"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Transport & headers"
words: 209
---

# GDPR/ePrivacy cookie-consent audit

**check_id**: `cookie_consent`
**aggressive**: no
**category**: Transport & headers
**max severity**: high
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1592.004 — Client Configurations

## What it does

GDPR / ePrivacy cookie-consent audit.

Loads the homepage WITHOUT any consent (fresh browser equivalent) and checks:
  1. Are non-essential cookies set on first page load? (analytics, marketing,
     third-party tracking) — that's a GDPR/ePrivacy violation in the EU.
  2. Is there a visible cookie banner in the HTML (heuristic)?

We don't try to BLOCK / accept the banner — we just check the cookies that
arrive on the first request and the presence of a banner in the rendered HTML.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | ⟨count⟩ non-essential cookie(s) set on first load and no consent banner visible | Install a consent-management platform (Complianz, CookieYes, Cookiebot, Klaro, Termly, Borlabs). Configure it to BLOCK third-party scripts (gtag, fbq, hotjar) until the user clicks Accept. Pre-loaded tracking cookies are a top-5 GDPR enforcement case under €/£/CHF jurisdictions. |
| medium | ⟨count⟩ non-essential cookie(s) set before consent (despite banner present) | Re-configure the consent plugin to actually block / dequeue tracking scripts until consent. Most plugins default to 'cookie-information mode' which doesn't block — switch to 'cookie-blocker' or 'pre-consent script management' mode. |
| info | Cookie-consent audit — no response from / | No action. |
| info | Cookie-consent posture looks compliant | No action. |
| info | No non-essential cookies on first load, no consent banner needed | No action. |

## Evidence the check records

- Cookie-consent audit — no response from /: GET / returned no body.
- ⟨count⟩ non-essential cookie(s) set on first load and no consent banner visible: Cookies set: ⟨value⟩ These cookies require prior opt-in consent under GDPR + ePrivacy in the EU (and similar laws in UK, CH, BR). No consent banner appears in the homepage HTML (checked against 20+ common consent-plugin markers).
- ⟨count⟩ non-essential cookie(s) set before consent (despite banner present): Cookies: ⟨value⟩ A consent banner is visible in the HTML, but cookies arrived BEFORE any user interaction. That's still non-compliant — the banner is decorative.
- No non-essential cookies on first load, no consent banner needed: Cookies set: ⟨value⟩
- Cookie-consent posture looks compliant: No non-essential cookies pre-consent. Banner markers present: ⟨has_banner⟩. Cookies on first load: ⟨value⟩.

## Compliance mapping

- **compliance_map / pci_dss**: n/a
- **compliance_map / nist_800_53**: PT-3
- **compliance_map / iso_27001**: A.5.34
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: MP.L1-3.8.3
- **compliance_v2 / nist_csf**: GV.OC-04
- **compliance_v2 / cis_v8**: 3.1
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan only cookie_consent https://example.com
```

`only` runs this check alone and prints its findings.
