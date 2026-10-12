---
id: privacy_inventory
title: "Privacy/GDPR data + tracker inventory (#16-23)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Privacy, compliance & accessibility"
words: 253
---

# Privacy/GDPR data + tracker inventory (#16-23)

**check_id**: `privacy_inventory`
**aggressive**: no
**category**: Privacy, compliance & accessibility
**max severity**: high
**OWASP**: A09:2021 — Security Logging & Monitoring Failures
**MITRE ATT&CK**: T1593 — Search Open Websites
**CWE**: CWE-359
**D3FEND**: D3-NTA

## What it does

Round-59 #16-23 — Privacy / GDPR data inventory + tracker audit.

#16 PII inventory — scan home page + checkout for visible PII fields
   (name/email/phone/address/credit-card patterns) so the data-map is
   one click rather than a manual walkthrough.
#17 Cookie-banner audit — is one present? does it block cookies before
   consent, or is it the cosmetic kind that ePrivacy regulators fine?
#18 Third-party JS exfil — list every third-party script src and the
   data they POST to (sample of inline `fetch(...)` strings).
#19 Google Fonts CJEU check — `fonts.googleapis.com` hits = the
   prohibited-without-consent pattern (per the German ruling).
#20 IP anonymisation — does `_gtag('config', {anonymize_ip: true})`
   appear in any inline script that loads GA/GA4?
#21 DPA helper — emit a structured list of every third-party processor
   detected, so the DPO can issue Data-Processing Agreements quickly.
#22 RTBE (right-to-be-erased) endpoint — is wp-admin/erase-personal-data
   reachable + correctly capability-gated?
#23 International data transfer — for every third-party processor,
   guess the jurisdiction (US/EU/UK) so transfer-impact assessment is
   one click.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high/low | PII patterns visible on home page (⟨value⟩ match(es)) | Customer-facing pages should not echo raw PII. If the matches are legitimate (contact email in footer), this is informational. CC/SSN matches on a public page are critical. |
| medium | Google Analytics detected without anonymize_ip | Add `gtag('config', 'GA_ID', {anonymize_ip: true});` OR migrate to GA4 (anonymisation is default). For EU compliance, also consider consent-mode v2 + a non-tracking analytics like Plausible/Fathom/Matomo. |
| medium | Google Fonts loaded directly from googleapis (CJEU 2022) | Self-host fonts (per German CJEU ruling, loading Google Fonts directly transfers IPs to the US without consent). Plugins: 'Local Google Fonts', 'OMGF' (Optimize My Google Fonts). |
| medium | No recognised cookie-consent banner detected | If you serve EU/UK visitors, ePrivacy + GDPR require informed consent BEFORE setting non-essential cookies. Install Cookiebot/Iubenda/Complianz or comparable. |
| medium | Right-to-be-erased admin page reachable unauthenticated | WordPress core gates this with `manage_options`. If you see the form anonymously, your `is_super_admin()` plugin or proxy strips auth — investigate. |
| low | Third-party JS processors detected: ⟨count⟩ | Each third party is a data processor. Issue a DPA with each one. For US-jurisdiction processors, document your Transfer Impact Assessment (TIA) per GDPR Art. 46. |
| info | Cookie-consent banner present | Confirm the banner blocks scripts BEFORE consent (most cosmetic banners don't). |
| info | Privacy inventory complete — no issues | No action. |
| info | Privacy inventory — could not fetch home page | Check connectivity. |

## Evidence the check records

- Privacy inventory — could not fetch home page: GET / returned no content.
- No recognised cookie-consent banner detected: None of: ⟨value⟩
- Cookie-consent banner present: Detected: ⟨value⟩
- Google Fonts loaded directly from googleapis (CJEU 2022): Detected fonts.googleapis.com or fonts.gstatic.com in HTML.
- Right-to-be-erased admin page reachable unauthenticated: GET /wp-admin/erase-personal-data.php -&gt; 200 (looks like the form rendered).
- Privacy inventory complete — no issues: No PII leaks, banner present, no tracker concerns.
- Google Analytics detected without anonymize_ip: Found GA/GTM script tag but no inline `anonymize_ip: true`.

## Compliance mapping

- **compliance_map / pci_dss**: 3.4.1
- **compliance_map / nist_800_53**: PT-3
- **compliance_map / iso_27001**: A.5.34
- **compliance_extra / hipaa**: 164.524
- **compliance_extra / soc2**: C1.1
- **compliance_extra / fedramp**: PT-3
- **compliance_extra / gdpr**: Article 30
- **compliance_v2 / hitrust**: 13.j
- **compliance_v2 / cmmc**: MP.L1-3.8.3
- **compliance_v2 / nist_csf**: GV.OC-04
- **compliance_v2 / cis_v8**: 3.1
- **compliance_v2 / iso_27001_2022**: A.5.34

## Run only this check

```
wpsecscan only privacy_inventory https://example.com
```

`only` runs this check alone and prints its findings.
