# Authenticated scans (login as admin)

Without auth, WPSecScan sees only the public surface. With auth, it sees
~3× more checks (admin endpoints, REST `?context=edit`, admin AJAX,
site-health internals).

## Quickest: WP Application Password (recommended)

WordPress 5.6+ ships Application Passwords. They are scoped per-tool
and revokable from the admin UI.

1. **In WP admin**: Users → Your profile → Application Passwords → "New
   application password" named `WPSecScan` → click Add.
2. **Copy the 4×6-char password shown once** (e.g. `aBcD EfGh IjKl MnOp`).
3. **Run with the App Password**:

```
wpsecscan --target https://yoursite.com \
          --auth-user admin \
          --auth-app-password 'aBcD EfGh IjKl MnOp'
```

When done, revoke the App Password in WP admin (the scanner doesn't
need it again until the next scan).

## Cookie-based login (legacy WP < 5.6)

```
wpsecscan --target https://yoursite.com --auth-user admin --auth-pass 'real-pw'
```

Posts to `/wp-login.php`, captures the `wordpress_logged_in_*` cookie,
reuses it across checks. Cookie is held in memory only.

## With 2FA

If the account requires TOTP (Two-Factor / Wordfence 2FA), pass the
code at runtime:

```
wpsecscan --target https://yoursite.com \
          --auth-user admin --auth-pass 'real-pw' \
          --auth-totp 123456
```

The scanner prompts interactively if `--auth-totp` is omitted and 2FA
is required.

## What auth unlocks

- **Full user roster** (`/wp-json/wp/v2/users?context=edit`) — emails, capabilities
- **Site Health** internals (`/wp-admin/site-health.php?action=site_health_get_directory_sizes`)
- **Plugin/theme update info** (`/wp-admin/admin-ajax.php?action=core-update-check`)
- **`wp-config.php` constants** indirectly via Site Health
- **Admin AJAX action surface** — every `add_action('wp_ajax_X')` callback

## Even better: install the [WP companion plugin](wp-plugin.md)

The companion plugin exposes a private REST endpoint that hands the
scanner the exact data it needs in one round-trip — no per-check probes,
no false positives from version-guessing.
