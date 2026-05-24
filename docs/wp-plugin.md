# WP companion plugin

`wpsecscan-companion` is a free, GPLv2+ WordPress plugin that exposes a
private REST endpoint for WPSecScan to pull authoritative diagnostics.

Without it, the scanner has to guess at plugin versions by HTTP-probing
`/wp-content/plugins/X/X.php`. With it, you get exact file hashes,
the cron schedule, active filters on auth endpoints, capability list,
Site Health output — all in one round-trip.

## Install

1. Download `wpsecscan-companion.zip` from the [latest release](https://github.com/bryanflowers/wpsecscan/releases/latest).
2. WP admin → Plugins → Add New → Upload Plugin → choose the .zip → Install Now → Activate.
3. The plugin adds a small admin page: **Settings → WPSecScan companion**.
4. Click **Generate one-time token**. Copy the token — it's shown once.

## Scan with the companion

```
wpsecscan --target https://yoursite.com \
          --companion-token 'pasted-token-here'
```

The scanner contacts `/wp-json/wpsecscan/v1/diagnostics` with the token.
The plugin validates it once, then invalidates it. The next scan
needs a fresh token.

## Privacy + security model

- **Token**: single-use, expires after 60 minutes if unused
- **Transport**: HTTPS only — the plugin refuses non-TLS requests
- **No write actions** — the endpoint is read-only
- **Output is sanitised**: no DB credentials, no AUTH_KEY salts, no
  user passwords, no plaintext API keys (these are masked)
- **Activity logged** in the companion admin page so you can audit when
  the scanner pulled data

## What the endpoint exposes

| Section | Content |
|---------|---------|
| `core` | WP version, multisite flag, install path (relative), language |
| `plugins[]` | slug, version, active, file_hash_sha256, update_available |
| `themes[]` | slug, version, active, file_hash_sha256, parent |
| `users[]` | login, email_hash, roles, last_login, 2fa_enabled |
| `cron[]` | hook, next_run, schedule, source_plugin |
| `auth_filters` | active `authenticate` / `wp_authenticate` filters |
| `site_health` | output of WP's built-in `WP_Site_Health` checks |
| `config_constants` | sanitised wp-config constants (no secrets) |

See the plugin source at [wp-plugin/wpsecscan-companion](https://github.com/bryanflowers/wpsecscan/tree/main/wp-plugin) for the exact field list.

## Uninstall

Plugins → Installed → WPSecScan companion → Deactivate → Delete.
Plugin removes its options + revokes any active token on deletion.
