# Authenticated scan

**check_id**: `authenticated`
**aggressive**: no
**OWASP**: A01:2021 — Broken Access Control
**MITRE ATT&CK**: T1078 — Valid Accounts

## What it does

Authenticated scan — logs in as an admin and inspects internal state.

Three login flows supported (preference order):
  1. WP Application Password (ctx['auth_app_password'] — WP 5.6+, recommended)
  2. Companion-plugin one-time token (ctx['companion_token'] — see wp-plugin/)
  3. Cookie-based wp-login.php form POST (ctx['auth_user']/['auth_pass'])
     - 2FA: if site requires TOTP, ctx['auth_totp'] is consumed automatically

Performs the following inspections once logged in:
  - /wp-admin/users.php → admin-role roster + 2FA-status fingerprint
  - /wp-admin/plugins.php → definitive plugin enumeration (active/inactive)
  - /wp-admin/themes.php → installed-but-inactive themes (attack surface)
  - /wp-admin/site-health.php → Site Health critical issues
  - /wp-admin/options.php → dangerous flags (default_role, registration)
  - /wp-admin/update-core.php → pending core/plugin/theme updates
  - /wp-json/wp/v2/users?context=edit → full user data (emails)
  - WP REST diagnostics via companion plugin if token is set

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.18

## Run only this check

```
wpsecscan --target https://example.com --only authenticated
```
