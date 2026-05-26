=== WPSecScan companion ===
Contributors: bryanflowers
Tags: security, scanner, hardening, vulnerabilities, defensive
Requires at least: 5.6
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Exposes a read-only, token-gated REST endpoint so the WPSecScan defensive scanner can pull authoritative diagnostics in one round-trip.

== Description ==

WPSecScan companion gives the [WPSecScan](https://github.com/bryanflowers/wpsecscan) defensive scanner authoritative data about your WordPress install — exact plugin / theme versions, file hashes, user roles, cron schedule, Site Health critical issues — without HTTP-probing 30+ paths and guessing.

The plugin **never writes anything**. It exposes a single read-only REST endpoint, gated by a one-time token you generate in WP admin. The token is hashed at rest, single-use, and expires after 60 minutes if unused.

= Security model =

* Token stored as a password hash (`wp_hash_password`) — never in plaintext on disk
* Single-use — consumed on the first successful read
* 60-minute expiry if unused
* HTTPS-only (refuses non-TLS requests unless `WPSECSCAN_COMPANION_ALLOW_HTTP` is defined)
* No write actions exposed
* Activity log on the admin page records every access (IP + timestamp)
* No DB credentials, AUTH_KEY salts, plaintext API keys, or user passwords are returned
* Emails are returned as SHA-256 hashes only

= What the endpoints return =

The companion plugin exposes nine read-only endpoints. All require the
same one-time token in the `X-WPSecScan-Token` header.

`/wp-json/wpsecscan/v1/diagnostics`

* `core`: WP version, multisite flag, PHP version, language
* `plugins[]`: slug, version, active, file hash, update_available
* `themes[]`: slug, version, active, parent, file hash
* `users[]`: login, email_hash, roles, last_login, 2fa_enabled
* `cron[]`: hook, next_run, schedule
* `auth_filters`: which plugin code has hooked `authenticate` etc.
* `site_health`: critical + recommended issues from WP_Site_Health
* `config_constants`: sanitised wp-config constants (no secrets)

`/wp-json/wpsecscan/v1/file-monitor`

* Rolling SHA-256 manifest of every file under the active plugin +
  theme directories. The external scanner compares the manifest
  against the prior one and surfaces any diff as a critical finding
  (most file changes outside upgrade windows are tampering).

`/wp-json/wpsecscan/v1/app-passwords-policy`

* Whether the WP Application-Passwords feature is enabled, the
  configured auth-cookie expiration, and which (if any) IP-
  restriction plugins are active so the scanner can flag an
  unconstrained AP exposure.

`/wp-json/wpsecscan/v1/slow-query-log`

* Reports whether MySQL's `slow_query_log_file` is configured inside
  the document root (a common cheap-shared-hosting misconfig that
  lets visitors download production query logs).

`/wp-json/wpsecscan/v1/failed-login-geo` *(v1.1.0)*

* Last 7 days of failed-login source IPs grouped by IP with hit
  counts, sourced from Wordfence (wfLogins) or Solid Security
  (itsec_logs) audit tables when present.

`/wp-json/wpsecscan/v1/admin-login-sources` *(v1.1.0)*

* Last 50 administrator session sources (IP + login timestamp +
  user-agent), read from WordPress's per-user `session_tokens`
  meta. The scanner cross-references these against the public
  Tor exit-node list.

`/wp-json/wpsecscan/v1/backups` *(v1.1.0)*

* Detects UpdraftPlus, BlogVault, and Solid Backups, returning the
  last successful backup timestamp and off-site destination so the
  scanner can flag stale or missing backups.

`/wp-json/wpsecscan/v1/file-perms` *(v1.1.0)*

* Octal mode + world/group-writable flags for the four most-
  impactful paths: `wp-config.php`, `wp-content/`, `uploads/`,
  `plugins/`.

`/wp-json/wpsecscan/v1/2fa-enforcement` *(v1.1.0)*

* Detects Wordfence-Login-Security, WP-2FA, and Solid Security,
  reads the per-role enforcement policy, and flags admin-exempt
  configurations.

== Installation ==

1. Upload + activate
2. Settings → WPSecScan → Generate one-time token
3. Copy the token (shown once)
4. Run: `wpsecscan --target https://yoursite.com --companion-token 'PASTED'`

== Frequently Asked Questions ==

= Does this plugin send my data to a third-party server? =

No. The plugin only exposes a read-only REST endpoint on your own server. Nothing is sent anywhere. The scanner running on your machine connects to your WP site directly to read the diagnostics.

= Why do I need this plugin if WPSecScan already works without it? =

Without the plugin, the scanner has to HTTP-probe 30+ paths and guess at plugin versions. With it, you get exact data (file hashes, cron, auth filters, Site Health) in a single REST call. Result: ~3× more accurate plugin/theme detection and zero false positives from version-guessing.

= What permissions does the plugin require? =

`manage_options` (admin only) — to generate / revoke tokens on the settings page. The REST endpoint itself doesn't require WordPress login; it requires a valid one-time token in the `X-WPSecScan-Token` header.

= Is the token safe? =

Yes:
* Stored as a password hash via `wp_hash_password()` — never plaintext
* Single-use — invalidated the first time it's read
* Expires after 60 minutes if unused
* Requires HTTPS unless explicitly opted out via constant
* Every access is logged on the admin page with IP + timestamp

= What happens if I deactivate or delete the plugin? =

Deactivation revokes any active token. Deletion (Plugins → Delete) wipes all plugin options + activity log via `uninstall.php`.

= Can I use this with WP Multisite? =

Yes. The plugin must be Network Activated to expose the endpoint on every sub-site. Each sub-site generates its own tokens independently.

= Does it work without the WPSecScan scanner? =

Yes — you can hit the endpoint with `curl` for your own diagnostics. The scanner is just the most convenient consumer.

== Screenshots ==

1. Settings → WPSecScan admin page with "Generate one-time token" button
2. Activity log showing recent scanner accesses (timestamp + IP + sections returned)
3. Example diagnostics JSON returned from the REST endpoint

== Changelog ==

= 1.1.0 =
* Five new read-only REST endpoints feeding the v2.4.0 scanner:
  `/failed-login-geo`, `/admin-login-sources`, `/backups`,
  `/file-perms`, `/2fa-enforcement`.
* Token model upgraded from single-use to up-to-10-reads within the
  same 60-minute TTL so one scan can pull all nine endpoints with
  one token instead of requiring nine separate generations.
* No write actions added — every new endpoint reads-only, gated by
  the same HTTPS + token + audit-log model as v1.0.0.

= 1.0.0 =
* Initial release
* Read-only REST endpoint at `/wp-json/wpsecscan/v1/diagnostics`
* Token-gated, single-use, 60-min TTL, hashed at rest
* HTTPS-only enforcement
* Activity log on admin page

== Upgrade Notice ==

= 1.1.0 =
Adds five new diagnostic endpoints (failed-login geo, admin-login
sources, backup status, file permissions, 2FA enforcement) and
relaxes the single-use token to ≤10 reads within the same TTL so a
full scan only needs one token. No write actions, same security
model.

= 1.0.0 =
Initial release.
