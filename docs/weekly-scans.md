# Weekly auto-scan + dashboard

WPSecScan can manage a list of your sites, scan them on a schedule, and
show a single dashboard with risk-score trends, never-resolved findings,
and what changed since the last scan.

## Add sites

GUI: **Tools → Sites → Add site** → paste URL → tick "weekly scan" →
optionally add Application Password creds (see [auth](auth.md)).

CLI:
```
wpsecscan sites add https://site-a.com --weekly
wpsecscan sites add https://site-b.com --weekly --auth-user admin --auth-app-password '…'
wpsecscan sites list
wpsecscan sites remove https://site-a.com
```

Sites + creds (DPAPI-encrypted on Windows, gpg-encrypted elsewhere)
live in `~/.wpsecscan/sites.json`.

## Schedule

The installer offers to register the scheduler. To do it manually:

**Windows**:
```
wpsecscan schedule install --weekly --time 03:00
```
Registers a Windows Task Scheduler entry. Removes with:
```
wpsecscan schedule uninstall
```

**Linux / macOS**:
```
wpsecscan schedule install --weekly --time 03:00
# writes ~/.config/systemd/user/wpsecscan-weekly.{service,timer}
# OR ~/Library/LaunchAgents/com.wpsecscan.weekly.plist on macOS
```

## Dashboard

GUI: **Tools → Dashboard** opens a tab with:

- one row per site
- columns: last scan time, risk score (with sparkline trend), critical/high
  open count, never-resolved (>30 days) count, "what changed" link
- click any row → opens the site's latest report
- click "diff" → shows only findings new since the last scan

## Email digest

Once a week (configurable), a digest is mailed to `WPSECSCAN_DIGEST_EMAIL`
listing all critical/high findings across all sites. Set up:

```
wpsecscan digest configure --to ops@mycorp.com --smtp smtp.gmail.com:587 --from alerts@mycorp.com
wpsecscan digest test          # sends a test email
```

Uses the bundled `notify.py` backends — SMTP, Slack webhook, or Resend API.

## Disabling without uninstalling

```
wpsecscan schedule pause
wpsecscan schedule resume
```
