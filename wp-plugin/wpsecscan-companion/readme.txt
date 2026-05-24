=== WPSecScan companion ===
Contributors: bryanflowers
Tags: security, scanner, hardening, vulnerabilities, defensive
Requires at least: 5.6
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
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

= What the endpoint returns =

`/wp-json/wpsecscan/v1/diagnostics`

* `core`: WP version, multisite flag, PHP version, language
* `plugins[]`: slug, version, active, file hash, update_available
* `themes[]`: slug, version, active, parent, file hash
* `users[]`: login, email_hash, roles, last_login, 2fa_enabled
* `cron[]`: hook, next_run, schedule
* `auth_filters`: which plugin code has hooked `authenticate` etc.
* `site_health`: critical + recommended issues from WP_Site_Health
* `config_constants`: sanitised wp-config constants (no secrets)

== Installation ==

1. Upload + activate
2. Settings → WPSecScan → Generate one-time token
3. Copy the token (shown once)
4. Run: `wpsecscan --target https://yoursite.com --companion-token 'PASTED'`

== Changelog ==

= 1.0.0 =
* Initial release
