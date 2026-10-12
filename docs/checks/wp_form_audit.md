---
id: wp_form_audit
title: "Form-plugin deep audit (CF7/WPF/GF/NF/FF/Formidable) (#3)"
severity_max: high
severity_dynamic: false
aggressive: false
category: "WordPress core, plugins & themes"
words: 123
---

# Form-plugin deep audit (CF7/WPF/GF/NF/FF/Formidable) (#3)

**check_id**: `wp_form_audit`
**aggressive**: no
**category**: WordPress core, plugins & themes
**max severity**: high
**OWASP**: A05:2021 — Security Misconfiguration
**MITRE ATT&CK**: T1190 — Exploit Public-Facing Application
**CWE**: CWE-200
**D3FEND**: D3-NTA

## What it does

Round-59 #3 — Form-plugin deep audit.

Contact Form 7, WPForms, Gravity Forms, Ninja Forms, Formidable Forms.
Form plugins are the single highest stored-XSS + unauth file-upload
surface in WP. We:
  - fingerprint each form plugin (path + version)
  - flag missing `wpcf7-recaptcha`/`wpforms-recaptcha` indicators
  - check `/wp-json/contact-form-7/v1/contact-forms` (CF7 leak — should be auth)
  - probe NF/GF default upload-handler path

## Request footprint

The module contains 4 request call(s) to the target (GET x4). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Gravity Forms upload directory listable | Block directory listing for ⟨GF_UPLOAD⟩. Set `gform_upload_path` filter to a private path outside wp-content/uploads. |
| high | Ninja Forms deprecated upload directory listable | Add an empty index.html in ⟨NF_UPLOAD⟩ and disable directory listing in nginx/.htaccess. The deprecated handler is a known stored-XSS path. |
| medium | Contact Form 7 REST endpoint readable unauthenticated | CF7 REST should require `cap=manage_options`. Apply the upstream fix in v5.9.5+, and check the `rest_authentication_errors` filter on your install. |
| info | Form plugin(s) detected: ⟨count⟩ | Form plugins are the most common stored-XSS + unauth-upload entry point. Keep all of them on the latest minor. |
| info | Form-plugin audit — no popular form plugins detected | No action. |

## Evidence the check records

- Form-plugin audit — no popular form plugins detected: Probed 6 form plugins.
- Contact Form 7 REST endpoint readable unauthenticated: GET ⟨CF7_REST⟩ -&gt; ⟨value⟩ (⟨count⟩ bytes). Form templates + any embedded merge tags are public.
- Ninja Forms deprecated upload directory listable: GET ⟨NF_UPLOAD⟩ returns a directory index.
- Gravity Forms upload directory listable: GET ⟨GF_UPLOAD⟩ returns a directory index — uploaded files enumerable.

## Compliance mapping

- **compliance_map / pci_dss**: 6.4.1
- **compliance_map / nist_800_53**: SI-10
- **compliance_map / iso_27001**: A.8.28
- **compliance_extra / hipaa**: 164.312(c)(1)
- **compliance_extra / soc2**: CC6.1
- **compliance_extra / fedramp**: SI-10
- **compliance_extra / gdpr**: Article 32
- **compliance_v2 / hitrust**: 06.h
- **compliance_v2 / cmmc**: CM.L2-3.4.1
- **compliance_v2 / nist_csf**: ID.AM-02
- **compliance_v2 / cis_v8**: 2.1
- **compliance_v2 / iso_27001_2022**: A.8.8

## Run only this check

```
wpsecscan only wp_form_audit https://example.com
```

`only` runs this check alone and prints its findings.
