# Form-plugin deep audit (CF7/WPF/GF/NF/FF/Formidable) (#3)

**check_id**: `wp_form_audit`
**aggressive**: no
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
wpsecscan --target https://example.com --only wp_form_audit
```
