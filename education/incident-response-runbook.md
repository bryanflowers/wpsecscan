# Incident response runbook — compromised WordPress site

Round-64 #159 — step-by-step playbook for "my site got hacked".

## Stop. Breathe. Document.

Before doing anything destructive, take screenshots / save copies of:
- The current state of the WP admin (Users list, Plugins list, recent
  Posts)
- The web-server log entries showing the attack
- Any visible defacement / injected content
- Files modified in the last 7 days (`find wp-content -mtime -7`)

You'll need these for: insurance claims, law enforcement, PCI
notification (if you process cards).

## Step 1 — Contain (first 15 min)

1. Put the site in maintenance mode (host control panel) OR rewrite
   `index.php` to serve a static "we're investigating" HTML
2. Disable PHP execution in `wp-content/uploads`:
   ```apache
   <FilesMatch "\.(?:php|phar)$">
     Require all denied
   </FilesMatch>
   ```
3. Take a forensic snapshot of `wp-content/` + the database BEFORE
   any cleanup (you'll thank yourself in step 5)

## Step 2 — Identify (first 60 min)

Run WPSecScan, focus on:
- `wpcron_suspicious_jobs` — webshell persistence
- `db_trigger_audit` — DB-level persistence
- `core_tampering` — modified core files
- `magecart_skimmer_patterns` — payment-page injection
- `cryptominer_js_injection` — miner injection

Cross-reference with:
- Wordfence scan results
- Web server access log for unusual paths
- WP audit log (if you have one — companion plugin's audit endpoint)

Identify the timeline: when was the first malicious change?

## Step 3 — Eradicate

For each compromise vector:

### Webshell file
- Identify all copies (often dropped in `wp-content/uploads/{year}/{month}/`
  or `wp-content/plugins/<slug>/.tmp.php`)
- Delete + audit your file-upload settings
- Check the original entry vector (plugin CVE? stolen creds?)

### Backdoor in plugin
- Uninstall the plugin
- Audit other plugins from the same source
- Read SECURITY-ACK.md style writeups in WPVulnerability for the
  original disclosure

### Compromised admin account
- Delete the unknown admin user
- Audit all other admins for last-login timestamps
- Rotate every active admin's password

### DB-level injection (wp_options bad URLs, fake admin via DB)
- Identify all malicious rows (saved screenshot in step 1 helps)
- Take a fresh DB backup, then DELETE the bad rows
- Search for triggers: `SHOW TRIGGERS;`

## Step 4 — Restore

PREFERRED: restore from a known-clean backup taken BEFORE the
compromise.

If no clean backup:
- Fresh WordPress install on a clean server
- Re-install plugins from official sources
- Re-import content from sanitised DB export
- Recreate admin users with new passwords
- Restore uploads after AV-scanning each file

## Step 5 — Rotate

After restore, rotate:
- All admin passwords
- All WordPress salts (`wp config shuffle-salts` or edit wp-config.php)
- All plugin API keys (Stripe, Mailchimp, etc.)
- All wp-cli auth tokens
- The DB user's password (`mysql -u root -e "ALTER USER..."`)

## Step 6 — Notify

If PCI-applicable (you process cards): notify acquiring bank within
24h.

If GDPR-applicable (you store EU user data): notify supervisory
authority within 72h IF personal data was likely exposed.

If you have customers: be proactive. A short, honest "we detected an
incident, here's what we know" beats radio silence.

## Step 7 — Post-mortem

Within 7 days, write up:
- Timeline (initial compromise → discovery → containment → eradication)
- Root cause (what specific bug/credential/config let them in?)
- What we did right (caught it within X hours via Y)
- What we did wrong (didn't have backup; admin reuse; missing MFA)
- Action items (with owners + deadlines)

Share publicly if you can — the community learns from it.

## When to call professionals

- You can't confirm the original entry vector
- The DB has unfamiliar tables / triggers / stored procedures
- You don't trust your own backups
- Customer card data was likely accessed
- You're outside your comfort zone in step 3

Reasonable per-incident cost: $2k-$20k for a small WP site. Worth
every penny if customer trust is on the line.

## Prevention (for next time)

- Daily off-site backups + monthly tested restore
- MFA on every admin account
- WPSecScan in daemon mode with Slack alerts
- Quarterly internal audit
- Web Application Firewall (Wordfence Premium, Sucuri, Cloudflare)
- Plugin update discipline (within 48h of patch release for critical)
