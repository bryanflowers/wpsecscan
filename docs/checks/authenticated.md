---
id: authenticated
title: "Authenticated scan"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authenticated"
words: 308
---

# Authenticated scan

**check_id**: `authenticated`
**aggressive**: no
**category**: Authenticated
**max severity**: high
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

## Request footprint

The module contains 9 request call(s) to the target (GET x6, POST x3). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Companion: Site Health critical issues (⟨count⟩) | Resolve every Site Health critical issue. |
| high | Dangerous WordPress option(s) | Set default_role to 'subscriber'. Disable user registration unless you actually need it. Audit every Settings page after install. |
| high/medium | Pending updates in wp-admin | Apply pending updates. Old core/plugin/theme = #1 cause of WordPress compromise. |
| high | WordPress Site Health flags ⟨crit_count⟩ critical issue(s) | Resolve every Site Health critical issue. They cover PHP version, autoupdate, REST availability, scheduled events. |
| high | ⟨count⟩ administrator(s) without 2FA | Enable 2FA on every administrator account. The Two-Factor core-team plugin is the canonical choice. |
| medium | Authentication failed — credentials rejected or 2FA prompt unhandled | Verify credentials. For 2FA, generate an Application Password instead. |
| medium | Authentication failed — ⟨cat⟩ | Set WPSECSCAN_AUTH_DEBUG=1 and re-run to see a step-by-step log at ~/.wpsecscan/auth-debug/{host}.log. For 2FA, generate an Application Password and use --auth-app-password instead of --auth-pass. |
| medium | WPSecScan companion plugin returned ⟨value⟩ | Generate a fresh token in WP admin → Settings → WPSecScan companion. |
| medium | ⟨count⟩ administrator account(s) (HTML) | Audit + reduce admin count. Force 2FA. |
| medium | ⟨count⟩ administrator account(s) (REST) | Audit each admin. Demote anyone who doesn't need admin. Force 2FA on all admin accounts. |
| low | ⟨count⟩ inactive theme(s) installed | Delete every theme you're not using. Keep at most one fallback (e.g. twentytwentyfive). |
| low | ⟨count⟩ user(s) with no last_login meta | Audit for inactive accounts and delete or downgrade them. |
| info | Authenticated as ⟨user⟩ via ⟨auth_method⟩ | No action. |
| info | Authenticated scan completed with no critical issues | No action needed. |
| info | Authenticated scan skipped (no credentials) | No action needed. |
| info | Companion plugin not reachable | Install + activate the WPSecScan companion plugin, or fall through to cookie auth. |
| info | Companion: WordPress core v⟨value⟩ | Keep core current. |
| info | Companion: ⟨count⟩ plugins (⟨count⟩ active, ⟨count⟩ need update) | Apply updates; delete inactive plugins. |
| info | Definitive plugin list: ⟨count⟩ active, ⟨count⟩ inactive | Delete inactive plugins — they still receive PHP execution if a CVE drops while installed. |

## Evidence the check records

- Authenticated as ⟨user⟩ via ⟨auth_method⟩: Authenticated checks will now run.
- Authenticated scan skipped (no credentials): Pass --auth-user + (--auth-pass OR --auth-app-password), OR --companion-token (with the companion plugin installed).
- Authenticated scan completed with no critical issues: Logged in via ⟨auth_method⟩ and inspected users, plugins, themes, options, Site Health, updates.
- Companion: WordPress core v⟨value⟩: multisite=⟨value⟩, language=⟨value⟩
- WPSecScan companion plugin returned ⟨value⟩: GET /wp-json/wpsecscan/v1/diagnostics -&gt; ⟨value⟩. Token may be invalid, expired, or already used.
- Authentication failed — credentials rejected or 2FA prompt unhandled: Neither App Password nor cookie login succeeded. If the site uses 2FA, supply --auth-totp &lt;code&gt;. If it uses a custom login URL (WPS Hide Login), the cookie flow can't find it.
- Companion plugin not reachable: HTTPError: ⟨value⟩
- ⟨count⟩ user(s) with no last_login meta: May indicate stale accounts that could be deleted.
- ⟨count⟩ administrator account(s) (HTML): Administrator-role users: ⟨value⟩
- Definitive plugin list: ⟨count⟩ active, ⟨count⟩ inactive: Active: ⟨value⟩ Inactive: ⟨value⟩
- ⟨count⟩ inactive theme(s) installed: Inactive themes still ship PHP that PHP-FPM will execute if requested.
- WordPress Site Health flags ⟨crit_count⟩ critical issue(s): See Tools → Site Health in wp-admin.

## Compliance mapping

- **compliance_map / pci_dss**: 8.2.1
- **compliance_map / nist_800_53**: AC-3
- **compliance_map / iso_27001**: A.5.18

## Run only this check

```
wpsecscan only authenticated https://example.com
```

`only` runs this check alone and prints its findings. Results that other checks normally share with it (WAF detection, plugin list, discovered users) are not populated in that mode.
