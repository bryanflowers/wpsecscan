---
id: email_obfuscation_audit
title: "Email obfuscation + raw-address leak audit"
severity_max: low
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 73
---

# Email obfuscation + raw-address leak audit

**check_id**: `email_obfuscation_audit`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: low
**OWASP**: A04:2021 — Insecure Design
**MITRE ATT&CK**: T1593 — Search Open Websites/Domains

## What it does

Email-obfuscation library detection + raw-email-still-in-source check.

Many sites install a JS library that "obfuscates" email addresses on the
front-end (Cloudflare email protection, Anti-Spam Email, Email Encoder
Bundle, etc). Two problems:
  1. The obfuscation is trivially reversible (all client-side); spam
     scrapers cracked these years ago.
  2. The raw email is often STILL present somewhere in the HTML / JS
     bundle, defeating the obfuscation.
  3. Screen readers break on obfuscated `mailto:` links → a11y regression.

## Request footprint

The module contains 1 request call(s) to the target (GET x1). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| low/info | Email obfuscation in use but raw addresses still leak / Email-obfuscation library in use (information only) | Client-side email obfuscation is cosmetic — all current libraries are trivially reversed by modern scrapers. The right defences are: 1. Use a contact form (no mailto: anywhere) 2. Image-based addresses for low-volume contact pages 3. Trust your spam filter (Gmail/Microsoft do this well) Obfuscation also breaks screen readers (a11y regression). Verify the obfuscator's mailto: output passes accessibility audits. |

## Compliance mapping

- **compliance_map / pci_dss**: 12.5.3
- **compliance_map / nist_800_53**: PL-4
- **compliance_map / iso_27001**: A.5.10
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: AC.L2-3.1.20
- **compliance_v2 / nist_csf**: PR.AC-04
- **compliance_v2 / cis_v8**: 3.3
- **compliance_v2 / iso_27001_2022**: A.5.10

## Run only this check

```
wpsecscan only email_obfuscation_audit https://example.com
```

`only` runs this check alone and prints its findings.
