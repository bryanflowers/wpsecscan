# WordPress Security 101

Round-64 #158 — beginner crash course.

## You should care if...

- You run a WordPress site for a business or organisation
- Your livelihood, reputation, or customers' data are on it
- You don't know what "MFA" or "wp-config.php" mean — that's exactly
  who this is for

## The 10 things to do TODAY

### 1. Update WordPress core

Dashboard → Updates → click the big button. Do this monthly.

### 2. Update every plugin + theme

Same Updates page. Uninstall plugins you don't use — every installed
plugin is attack surface even if "deactivated".

### 3. Use unique, strong passwords

A password manager (Bitwarden, 1Password) makes this easy. Reuse
nothing.

### 4. Enable two-factor auth (MFA) on every admin account

Plugin: "WP 2FA" or "Two Factor". Without MFA, a stolen password =
full takeover.

### 5. Limit who has admin rights

Editors, authors, contributors — give the lowest role that gets the
job done. Audit your users list monthly.

### 6. Pick a reputable host

Look for: SSL/HTTPS by default, automatic WordPress core updates,
daily off-site backups, easy restore. Examples: WP Engine, Kinsta,
Pressable, SiteGround. Avoid the cheapest tier of generic shared
hosts.

### 7. Install a free WAF/scanner

Wordfence (free) or Sucuri (free) blocks common attacks at the
WordPress layer. WPSecScan (free) audits your config + flags issues
the WAF can't.

### 8. Enable HTTPS — and HSTS

Most hosts handle HTTPS now. If yours doesn't, ask them to set it up
or migrate. HSTS forces browsers to use HTTPS even if a user types
http:// — your host should expose a one-click toggle.

### 9. Back up DAILY, off-site, and TEST a restore

Backups you've never restored are worthless. Plugins like
"UpdraftPlus" or "WP Time Capsule" can upload to S3/Drive/etc. Test
a restore on a staging site twice a year.

### 10. Don't install nulled plugins

"Nulled" / "free pirated premium" plugins are almost always backdoored.
Pay for the real one or use a free alternative. Saving $79/year by
installing a backdoor is a bad trade.

## Don't fall for these myths

- ❌ "Security plugins fix everything" — they help; they don't fix
  bad passwords, outdated plugins, or admin user negligence
- ❌ "My site is too small to be a target" — automated scanners hit
  every WP site every day; there is no "too small"
- ❌ "I'll deal with it after I get hacked" — recovery is 10-100×
  the cost of prevention
- ❌ "HTTPS = secure" — HTTPS protects data in transit only; it
  doesn't fix application-layer flaws

## When (not if) something goes wrong

1. Take the site offline immediately (host's maintenance mode)
2. Restore from a known-clean backup
3. Rotate ALL passwords + WordPress salts (in wp-config.php)
4. Audit user list — delete unknown admins
5. Run a clean scan with WPSecScan + Wordfence
6. Call a professional if any of step 1-5 confuses you

## Where to learn more

- WordPress official security: <https://wordpress.org/about/security/>
- WPSecScan docs: <https://github.com/bryanflowers/wpsecscan>
- OWASP for WordPress: search "OWASP WordPress security"
- This MOOC: see [mooc-outline.md](mooc-outline.md)

## Bottom line

WordPress security is 80% hygiene (updates, passwords, backups, MFA)
and 20% tools. Do the hygiene first; the tools are for catching the
20% you'd miss.
