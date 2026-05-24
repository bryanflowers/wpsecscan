# Submitting WPSecScan companion to the wp.org plugin directory

This is the **manual** part of getting `wpsecscan-companion` listed in
the official WordPress.org plugin directory. The code is ready
(audited + compliant); the submission itself requires a real human at a
real wp.org account.

Expected timeline: 1-2 weeks from submission to listing.

## 1. Pre-flight check (already done in v1.10.0)

These are all already in place:

- [x] `Plugin Name`, `Plugin URI`, `Version`, `Requires at least`,
      `Requires PHP`, `Author`, `License`, `License URI`, `Text Domain`,
      `Domain Path` headers all present in `wpsecscan-companion.php`
- [x] `load_plugin_textdomain()` called on `plugins_loaded`
- [x] `languages/` directory exists
- [x] `readme.txt` with required sections: Description, Installation,
      FAQ, Screenshots, Changelog, Upgrade Notice
- [x] `Stable tag: 1.0.0` matches `Version: 1.0.0`
- [x] Tags ≤ 5
- [x] GPL-2.0-or-later licence, compatible with wp.org requirement
- [x] No obfuscated / minified code
- [x] No "calling home" or external HTTP requests from the plugin
- [x] ABSPATH guard on every PHP file
- [x] Capability checks, nonces, output escaping, input sanitisation
- [x] Activity log + token hashing (security best practices)
- [x] Placeholder banners + icons + 3 screenshots in `assets/`
- [x] Uninstall.php wipes options on plugin delete

Verify with WordPress's official tooling before submitting:

```bash
# 1. Plugin Check (wp.org's official linter)
wp plugin install plugin-check --activate
wp plugin verify-checksums wpsecscan-companion

# 2. PHP CodeSniffer with WordPress standards
composer global require wp-coding-standards/wpcs
phpcs --standard=WordPress wp-plugin/wpsecscan-companion/
```

## 2. Create a wp.org account

1. Go to https://login.wordpress.org/register
2. Verify your email
3. Enable 2FA (Account → Security → Two-Factor Options).
   The plugin directory requires 2FA for submission.

## 3. Submit the plugin for review

1. Visit https://wordpress.org/plugins/developers/add/
2. Upload `dist/wpsecscan-companion.zip`
   (build with: `python scripts/build-wp-plugin.py`)
3. Confirm the plugin slug — must be unique. Probably `wpsecscan-companion`
   will be accepted; if not, try `wpsecscan-diag` or similar.
4. Submit.

You will receive an email confirmation. A wp.org plugin reviewer will
manually check the code within ~5-14 days.

## 4. Respond to review feedback

Common things reviewers ask:

- **"Why does your plugin name include 'WP'?"** — answer: WPSecScan is
  a project name, the companion is the helper. Many existing plugins
  use "WP" prefix (WP Mail SMTP, WP Rocket, etc.) and reviewers usually
  accept this when the project clearly markets itself separately.

- **"This is a companion plugin — does WPSecScan itself need to be hosted?"**
  Answer: No. WPSecScan runs entirely on the user's local machine; the
  companion just exposes a read-only REST endpoint that the local
  scanner can query. Link to the GitHub repo + AGPLv3 source.

- **"Sanitise this input / escape this output"** — fix in the code,
  bump the version (`1.0.0` → `1.0.1`), update `Stable tag` + `Changelog`,
  reply to the email with the fix.

## 5. After approval — SVN dance

Once approved, you'll get SVN credentials for a repo at:
`https://plugins.svn.wordpress.org/wpsecscan-companion/`

### One-time setup

```bash
mkdir wp-svn && cd wp-svn
svn co https://plugins.svn.wordpress.org/wpsecscan-companion/ .
```

### Layout

```
wpsecscan-companion/
├── trunk/                  # current development
│   ├── wpsecscan-companion.php
│   ├── includes/
│   ├── languages/
│   ├── readme.txt
│   └── uninstall.php
├── tags/                   # per-version snapshots
│   └── 1.0.0/              # MUST match Stable Tag in readme.txt
└── assets/                 # NOT inside the plugin folder — sibling
    ├── banner-1544x500.png
    ├── banner-772x250.png
    ├── icon-128x128.png
    ├── icon-256x256.png
    ├── screenshot-1.png
    ├── screenshot-2.png
    └── screenshot-3.png
```

### Copy your code into trunk

```bash
# From the wpsecscan repo:
cp -r wp-plugin/wpsecscan-companion/wpsecscan-companion.php   wp-svn/trunk/
cp -r wp-plugin/wpsecscan-companion/includes                   wp-svn/trunk/
cp -r wp-plugin/wpsecscan-companion/languages                  wp-svn/trunk/
cp    wp-plugin/wpsecscan-companion/readme.txt                 wp-svn/trunk/
cp    wp-plugin/wpsecscan-companion/uninstall.php              wp-svn/trunk/

# Assets — sibling to trunk, not inside it
mkdir -p wp-svn/assets
cp wp-plugin/wpsecscan-companion/assets/*.png  wp-svn/assets/
```

### Tag the release

```bash
cd wp-svn
svn cp trunk tags/1.0.0
svn add --force trunk/* assets/* tags/*
svn ci -m "Release 1.0.0 — initial wp.org publication"
```

You'll be prompted for your wp.org credentials. After commit, the
listing usually appears within ~15 minutes at
`https://wordpress.org/plugins/wpsecscan-companion/`.

## 6. Publishing updates

Update workflow:

1. Bump version in `wpsecscan-companion.php` header AND `readme.txt`'s
   `Stable tag` (they must match!).
2. Update `== Changelog ==` and `== Upgrade Notice ==` sections.
3. Copy changes into `wp-svn/trunk/`.
4. `svn cp trunk tags/X.Y.Z`
5. `svn ci -m "Release X.Y.Z — short summary"`

If you only change `assets/` (icon, banner, screenshot), you don't need
to bump the version — just commit the asset changes.

## 7. Common gotchas

- **`Stable tag` mismatch**: if `readme.txt` says `Stable tag: 1.0.0`
  but you only committed `trunk/`, wp.org will show v1.0.0 from trunk —
  but updates won't fire to users until you also commit to `tags/1.0.0/`.
- **Asset format**: PNG only for icons + banners. JPG is rejected.
- **Banner naming**: must be exactly `banner-1544x500.png` and
  `banner-772x250.png`. No `_` separator.
- **Screenshot order**: numbered consecutively starting at 1
  (`screenshot-1.png`, `screenshot-2.png`...). Numbers in `readme.txt`'s
  `== Screenshots ==` section must match.

## 8. After listing — replace placeholder assets

The bundled assets are placeholder text-on-bg images generated by
`scripts/gen-wp-plugin-assets.py`. Replace them with real designs
before getting too many installs:

- **icon-256x256.png** — your logo, 256×256, transparent or solid bg
- **banner-1544x500.png** — hero image for the desktop plugin page
- **banner-772x250.png** — mobile banner (don't just resize the desktop one
  — text doesn't fit at half scale)
- **screenshot-*.png** — real WP admin screenshots, ideally 1280×800

Tools we recommend: Figma (free), Canva (free tier), or a designer on
Fiverr (~$30 total for icon + 2 banners).

## 9. Stats + reviews

After listing, monitor at:

- **Stats**: `https://wordpress.org/plugins/wpsecscan-companion/advanced/`
- **Reviews**: subscribe to the plugin's review feed
- **Support forum**: `https://wordpress.org/support/plugin/wpsecscan-companion/` —
  respond within 48h to keep your "active support" badge

## Cannot automate

These steps cannot be done from the WPSecScan codebase or this guide
— you must perform them manually:

- Creating the wp.org account
- Submitting the plugin slug request
- Replying to reviewer emails
- Running `svn import` / `svn ci` (requires your credentials)
- Designing real banner / icon images
