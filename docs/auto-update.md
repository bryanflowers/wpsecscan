# Auto-updating WPSecScan

There are **three** things that get updated, on three different cadences.

| Layer | What it is | Default cadence | How to change |
|-------|------------|-----------------|---------------|
| **Scanner binary** | `wpsecscan.exe` / `wpsecscan-gui.exe` | Weekly check, manual download | `WPSECSCAN_NO_UPDATE_CHECK=1` to disable |
| **CVE database** | Wordfence/Patchstack/OSV vuln data → `~/.wpsecscan/vuln-db.json` | Daily refresh (round-61+) | `wpsecscan schedule install` registers it |
| **Exploit signatures** | Pattern data → `~/.wpsecscan/exploit_signatures.json` | On-demand | `wpsecscan db signatures` |

## Quick start — get fully automated

```bash
# Once, after install
wpsecscan sites add https://yoursite.com --weekly
wpsecscan schedule install --time 03:00      # Mon 03:00 scan + daily 02:00 DB refresh

# Optional: alerts when a NEW CVE lands for a plugin you have installed
wpsecscan db subscribe https://hooks.slack.com/services/T.../B.../xxx
```

That's it. From this point on:

- **Daily at 02:00** — your CVE DB refreshes (Wordfence + Patchstack + OSV)
- **Mondays at 03:00** — every site in your list gets scanned
- **Immediately** — if a new CVE matches one of your installed plugins, the
  webhook fires

## Manual commands

### Check status

```bash
wpsecscan db status
```

Output:
```
  source:        cache
  cache path:    /home/bryan/.wpsecscan/vuln-db.json
  cache exists:  True
  entries:       18,234
  age:           1 days
  stale:         False  (threshold 7 days)
```

### Force refresh

```bash
wpsecscan db update                          # Wordfence + Patchstack (if token set) + OSV
wpsecscan db signatures                      # exploit_signatures.json from GitHub raw
```

### Subscribe to new-CVE alerts

```bash
# Fire on any new CVE for any tracked plugin/theme:
wpsecscan db subscribe https://hooks.slack.com/services/T.../B.../xxx

# Only fire for one specific site:
wpsecscan db subscribe https://hooks.example/abc --site https://acme.com

# Friendly label for the subscription:
wpsecscan db subscribe https://hooks.example/abc --label ops-on-call

# Remove a subscription:
wpsecscan db unsubscribe https://hooks.slack.com/services/T.../B.../xxx
```

### Manually check for new alerts

```bash
wpsecscan db alert-check
```

This is what the scheduled task runs. Manually triggering it is useful
after `db update` to immediately notify on freshly-published CVEs.

## What the webhook receives

Each subscription POST is a single JSON object:

```json
{
  "event": "cve_alert",
  "site_url": "https://acme.com",
  "plugin_slug": "contact-form-7",
  "installed_version": "5.9.1",
  "cve": "CVE-2026-12345",
  "severity": "high",
  "title": "Authenticated CSRF in Contact Form 7"
}
```

Compatible with: Slack incoming webhooks, Discord webhooks (with
slight reformatting), generic HTTP receivers (n8n, Zapier, Make).

## API keys (optional)

Setting these env vars enriches the CVE DB:

```bash
export WPSECSCAN_PATCHSTACK_TOKEN=ps_...    # Patchstack premium feed
```

Wordfence Intelligence and OSV.dev are free, no key needed.

## Opting out

```bash
# Stop the scheduler entirely:
wpsecscan schedule uninstall

# Or temporarily pause it:
wpsecscan schedule pause
wpsecscan schedule resume

# Block all network from the scanner (air-gapped mode):
export WPSECSCAN_NO_NETWORK=1
```

## Privacy

- No telemetry. The scanner doesn't phone home.
- The binary-update check is a single GET against GitHub Releases —
  set `WPSECSCAN_NO_UPDATE_CHECK=1` to disable.
- CVE-DB fetches are public REST calls to wordfence.com / patchstack.com
  / osv.dev / api.github.com — your tracked sites are never sent
  anywhere.
- Webhook subscriptions live ONLY on your machine
  (`~/.wpsecscan/cve_subscriptions.json`). No registration with us.
