---
id: companion_advanced
title: "Companion v1.1 endpoints: failed-login geo, Tor admin, backups, perms, 2FA"
severity_max: high
severity_dynamic: false
aggressive: false
category: "Authentication & session"
words: 596
---

# Companion v1.1 endpoints: failed-login geo, Tor admin, backups, perms, 2FA

**check_id**: `companion_advanced`
**aggressive**: no
**category**: Authentication & session
**max severity**: high
**OWASP**: A07:2021 — Identification & Authentication Failures
**MITRE ATT&CK**: T1110.001 — Brute Force: Password Guessing
**CWE**: CWE-307
**D3FEND**: D3-AL

## What it does

Items #23-27 — consumers of the v1.1 companion-plugin endpoints.

Each endpoint requires a valid `--companion-token`. When none is set we
short-circuit silently so the check doesn't add noise.

#23 — failed-login geography: pull /failed-login-geo, join against the
     bundled GeoLite-Country country code, flag when 80%+ of recent
     failures come from one country or one ASN.
#24 — Tor admin logins: pull /admin-login-sources, cross-ref against the
     cached public Tor exit-node list.
#25 — backup status: pull /backups, flag if no run in 14d.
#26 — file-permissions: pull /file-perms, flag world-writable wp-config.
#27 — 2FA enforcement: pull /2fa-enforcement, flag admin-exempt.

## Request footprint

The module contains 2 request call(s) to the target (GET x2). Calls inside loops send more than one request, so treat this as a minimum.

This is a passive check: it runs without --aggressive.

## Findings this check can raise

| Severity | Finding | Remediation |
|----------|---------|-------------|
| high | Admin login from Tor exit node (⟨count⟩ session(s)) | Force a global session reset (Users → Edit → 'Log out everywhere'). Audit user_meta `session_tokens` for any remaining sessions. Add a Cloudflare WAF rule blocking /wp-login.php from `tor: yes` ASNs. |
| high/medium | World-writable WordPress paths (⟨count⟩) | Tighten permissions: chmod 600 wp-config.php chmod 755 wp-content/ uploads/ plugins/ World-writable wp-config.php means any process on the box (including a low-priv shell from another tenant) can read your DB password. |
| high | ⟨count⟩ cron hook(s) call shell-exec functions | Audit each flagged source file. Legitimate uses should be narrowly scoped (specific binary, escaped args). Anything that runs the cron-arg or option content through a shell command is almost certainly malware. |
| high/medium | ⟨count⟩ log file(s) exposed under web root | Move log files outside ABSPATH (e.g. /var/log/wp/{site}.log) or add a deny rule. Apache: `<FilesMatch "\.log$">Require all denied</FilesMatch>`. Nginx: `location ~ \.log$ { deny all; }`. |
| high/medium | ⟨n⟩ wp-cron hook(s) failing or overdue | Verify each hook's callback resolves cleanly (check Action Scheduler's admin page if WooCommerce is installed). For overdue wp-cron hooks, ensure WP_CRON_LOCK_TIMEOUT is not stuck and the site receives enough traffic to trigger wp-cron, OR install a system cron job hitting wp-cron.php. |
| medium | 2FA is configured but administrators are exempt | Open the 2FA plugin's policy page and add 'administrator' to the required-roles list. Admin accounts are the highest value target — leaving them exempt defeats the purpose. |
| medium | Admin account(s) with 3+ concurrent sessions (⟨count⟩ user(s)) | If unexpected: change the password + Force-log-out-everywhere in WP admin → Users → Profile. Then audit recent admin actions via the /recent-admin-actions endpoint. |
| medium | High failed-login volume from a single IP (⟨value⟩: ⟨value⟩ attempts in ⟨value⟩) | Install Wordfence or Solid Security and enable country-level blocking. Or add a Cloudflare WAF rule blocking the top attacker ASNs. Confirm 2FA is enforced for the administrator role (companion endpoint /2fa-enforcement). |
| medium | Last backup is ⟨days⟩ days old | Either fix the scheduled-backup cron or switch to a managed off-site solution (BlogVault, Jetpack VaultPress). Without recent off-site backups a ransomware or hosting-account-takeover means total data loss. |
| medium | No 2FA plugin active | Install Wordfence-Login-Security (free) or WP-2FA (free + premium tiers). Enforce TOTP for the administrator role at minimum. |
| medium | No backup plugin detected | Install one of: UpdraftPlus (free), BlogVault (paid, off-site by default), or Solid Backups. Configure off-site storage. |
| medium | SMTP plugin reports a recent send failure | Open the SMTP plugin's debug / test page in WP admin and send a test message; the failure reason is usually visible there. Common: missing/wrong API key, sending domain not verified. |
| medium | ⟨count⟩ PHP fatal error(s) in error_log | Track down the plugin / theme causing the fatals. The error log path is ⟨value⟩. Disable WP_DEBUG_DISPLAY in wp-config.php so fatals don't leak to visitors while you fix. |
| medium | ⟨count⟩ multisite blog(s) have 0 administrators | Network admin → Sites → click each blog → Users → promote one user to administrator, OR archive the blog if it should be retired. |
| low | WordPress transients occupy ⟨mb⟩ MB (⟨value⟩ rows) | Install Transients Manager (free) or run `wp transient delete --expired` via WP-CLI to clear expired entries. Persistent bloat usually traces back to one plugin — check the fattest names. |
| low | object-cache.php drop-in installed but not in use by core | Check the drop-in's admin panel (Redis / W3TC / LiteSpeed) — usually a 'Connect' or 'Enable' toggle is off, or the Redis/Memcached server is unreachable. |
| low | ⟨count⟩ DB table(s) abnormally large | Large _options often = transient bloat (clean with Transients Manager). Large _postmeta often = leftover plugin garbage (clean with WP-Optimize). Large _comments = spam — run an Akismet sweep. |
| low | ⟨count⟩ non-core cron hook(s) scheduled in last 7 days | Cross-reference each hook name against installed plugins. Hooks that look auto-generated (hex strings, base64-ish, single-letter names) deserve immediate investigation. |
| info | Companion advanced endpoints skipped (no --companion-token) | No action. |
| info | Companion advanced endpoints — no issues found | No action needed. |
| info | No SMTP plugin detected (wp_mail uses PHP mail()) | Install WP Mail SMTP (free, by WPForms) and configure a transactional provider (Mailgun, SendGrid, Amazon SES, or Brevo) to dramatically improve deliverability. |

## Evidence the check records

- Companion advanced endpoints skipped (no --companion-token): Items #23-27 require the companion plugin + a fresh single-use token.
- ⟨count⟩ log file(s) exposed under web root: These files live inside the web root and may be served verbatim by a misconfigured nginx/Apache: ⟨value⟩
- ⟨n⟩ wp-cron hook(s) failing or overdue: Stalled cron is a frequent indicator of malware persistence — attackers hijack a hook, then ensure WP can't run it to its scheduled completion: ⟨value⟩
- No SMTP plugin detected (wp_mail uses PHP mail()): No WP Mail SMTP / Fluent SMTP / Easy WP SMTP / Mailgun plugin is active. Default PHP mail() has poor deliverability — messages from this site are likely to land in spam.
- ⟨count⟩ cron hook(s) call shell-exec functions: These cron callbacks contain references to PHP's shell-exec family (exec/shell_exec/passthru/system/popen/proc_open). Legitimate uses exist (e.g. some imagick fallback paths) but cron hooks running shell commands are a classic command-injection backdoor pattern: ⟨value⟩
- Companion advanced endpoints — no issues found: Pulled the full v1.1 + v1.2 endpoint set with companion token at ⟨base⟩.
- High failed-login volume from a single IP (⟨value⟩: ⟨value⟩ attempts in ⟨value⟩): Top 5 attacking IPs in last ⟨value⟩: ⟨value⟩ Total: ⟨total⟩ failed logins across ⟨count⟩ IPs.
- Admin login from Tor exit node (⟨count⟩ session(s)): The following administrator sessions originated from a public Tor exit node: ⟨lines⟩ Legitimate admins generally don't log in over Tor. If unexpected, treat as compromised — change passwords, invalidate sessions, audit recent admin actions.
- No backup plugin detected: None of UpdraftPlus, BlogVault, or Solid Backups is active.
- No 2FA plugin active: None of Wordfence-Login-Security, WP-2FA, or Solid Security is active.
- Admin account(s) with 3+ concurrent sessions (⟨count⟩ user(s)): Multiple parallel admin sessions can indicate account compromise (the attacker is logged in alongside the real user): ⟨value⟩
- ⟨count⟩ PHP fatal error(s) in error_log: Last 5 fatal entries (PII stripped): ⟨value⟩
- ⟨count⟩ non-core cron hook(s) scheduled in last 7 days: Newly-scheduled hooks aren't intrinsically bad, but if they correspond to plugins you didn't install in the last week, they may be malware persistence: ⟨lines⟩
- WordPress transients occupy ⟨mb⟩ MB (⟨value⟩ rows): Transients are short-lived caches; &gt;50 MB of them is usually a plugin failing to expire them. Top 5 by size: ⟨lines⟩
- object-cache.php drop-in installed but not in use by core: Found drop-in at ⟨value⟩ (vendor: ⟨value⟩) but `wp_using_ext_object_cache()` returns False. Means the drop-in is dormant — performance gain is lost.
- ⟨count⟩ multisite blog(s) have 0 administrators: A sub-blog with no admin user is unmanageable + indicates either a deletion gap or an enumeration lure where someone could provision their own admin via the network admin interface: ⟨value⟩
- SMTP plugin reports a recent send failure: Plugins active: ⟨value⟩ Last failure: ⟨value⟩
- 2FA is configured but administrators are exempt: Plugins active: ⟨value⟩. Enforced roles: ⟨value⟩. Administrator is NOT in the enforced-roles list.
- Last backup is ⟨days⟩ days old: Latest successful backup: ⟨last⟩. Backup plugin: ⟨value⟩. Off-site destination: ⟨value⟩.

## Compliance mapping

- **compliance_map / pci_dss**: 8.4.2
- **compliance_map / nist_800_53**: AC-7
- **compliance_map / iso_27001**: A.5.17

## References

- https://check.torproject.org/exit-addresses

## Run only this check

```
wpsecscan only companion_advanced https://example.com
```

`only` runs this check alone and prints its findings.
