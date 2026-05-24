# Predictable upload paths

**check_id**: `upload_path_predictable`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1083 — File and Directory Discovery

## What it does

Predictable upload-path probe.

WordPress stores uploads at /wp-content/uploads/YYYY/MM/<file>. If directory
listing is off but the admin uploads files with predictable names (logo.png,
admin-screenshot.png, draft.pdf), an attacker can guess and access "private"
uploads that aren't linked from any page.

Probes ~20 common admin-uploaded filenames in the current month/year folder.
GET-only, low rate.

## Compliance mapping

- **compliance_map / pci_dss**: 9.4.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.8.9

## Run only this check

```
wpsecscan --target https://example.com --only upload_path_predictable
```
