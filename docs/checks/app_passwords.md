# Application Passwords audit

**check_id**: `app_passwords`
**aggressive**: no
**OWASP**: A07:2021 — Identification & Authn Failures
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

WordPress Application Passwords audit.

Since WP 5.6, Application Passwords are a built-in way for clients to
authenticate to the REST API without using the user password. They're great
for legitimate integrations and a constant target for attackers because:
  - The endpoint /wp-json/wp/v2/users/me?context=edit returns 401 with a
    WWW-Authenticate header that reveals whether Application Passwords are on.
  - The /wp-admin/profile.php?page=application-passwords surface is the
    creation flow.

This check looks for:
  - Whether the Application Passwords feature is enabled (info)
  - Whether the authorization endpoint at /wp-admin/authorize-application.php
    is reachable (info)
  - Whether the JWT alternative plugin is installed

## Compliance mapping

- **compliance_map / pci_dss**: 8.3.6
- **compliance_map / nist_800_53**: IA-5
- **compliance_map / iso_27001**: A.5.17
- **compliance_v2 / hitrust**: 01.b
- **compliance_v2 / cmmc**: IA.L2-3.5.3
- **compliance_v2 / nist_csf**: PR.AA-02
- **compliance_v2 / cis_v8**: 6.5
- **compliance_v2 / iso_27001_2022**: A.5.16

## Run only this check

```
wpsecscan --target https://example.com --only app_passwords
```
