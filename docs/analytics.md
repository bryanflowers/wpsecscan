# Usage analytics — what, why, how to disable

WPSecScan can record local usage analytics so we can see which
features get used (and which don't), and improve the tool over time.

The whole system is built around two promises:

1. **Default off.** Nothing is recorded until you explicitly opt-in.
2. **Local-first.** Events stay on your machine unless you ALSO
   configure an upload destination and opt-in to upload.

## Opting in

```bash
# Local-only (recommended; we can't see your data — but you can)
wpsecscan analytics enable

# With upload to our community endpoint
WPSECSCAN_ANALYTICS_UPLOAD_URL=https://analytics.wpsecscan.com \
  wpsecscan analytics enable
```

Or in the GUI: `Tools → Analytics options...`

## Inspecting what we'd send

```bash
wpsecscan analytics show           # last 50 events
wpsecscan analytics show 500       # last 500 events
wpsecscan analytics export ./my-events.jsonl
```

The file is JSON-lines — human-readable. Grep / cat / cut. Audit it
before any upload.

## What we record (when enabled)

| Event | Fields | Example |
|-------|--------|---------|
| `cli_command`   | subcommand, duration_ms, exit_status | `subcommand=scan duration_ms=12450 exit_status=ok` |
| `check_ran`     | check_id, duration_ms, finding_count_bucket | `check_id=tls_headers duration_ms=234 finding_count_bucket=1-5` |
| `gui_action`    | action_name, duration_ms | `action_name=open_finding_fix_panel duration_ms=12` |
| `feature_used`  | feature_name | `feature_name=ai_triage.severity_auto_tuner` |
| `report_export` | format, finding_count_bucket | `format=pdf finding_count_bucket=26-100` |

Counts are bucketed (`0` / `1-5` / `6-25` / `26-100` / `101-500` /
`500+`) so we can't fingerprint individual scans.

## What we DO NOT record

- ❌ Target URLs (not even hashed)
- ❌ Finding titles, evidence, remediation, URLs
- ❌ Site config (sites.json contents)
- ❌ API keys / secrets / tokens of any kind
- ❌ Hostname / IP / username (anonymous ID is a random UUID)
- ❌ Timestamps to higher precision than minute
- ❌ Anything that could link the dataset back to you

The recording function (`wpsecscan/analytics.py:record`) has an
**allowlist** of fields per event type. Any extra field you might
accidentally pass is dropped on the way in — defence in depth.

## Anonymous ID

A random UUID stored at `~/.wpsecscan/analytics/anonymous_id.txt`.
**Rotated every 90 days**, so even if data is uploaded, it's only
correlatable for a quarter. Never derived from anything that could
identify you.

## Forget me

```bash
wpsecscan analytics forget
```

- Deletes all local event logs + the anonymous ID
- If upload was enabled, posts a deletion request to the upload
  destination (server-side compliance, GDPR-style)

## Disabling

```bash
wpsecscan analytics disable
```

Stops recording. Your existing local data is preserved. Use
`forget` to delete it too.

## Status

```bash
wpsecscan analytics status
```

Shows: enabled / disabled, anonymous ID, event count, storage path,
upload destination (if any).

## Why opt-in instead of opt-out?

Because we promised — see [SECURITY.md](../SECURITY.md) and the
v2.1.0 release notes: "Zero telemetry — nothing flows back about
who runs it." Defaulting to ON would break that promise. We want
your data only if you decide we should have it.

## When you should NOT enable this

- You audit sites in regulated industries where any outbound
  telemetry violates policy
- You run WPSecScan inside an air-gapped environment
- You don't trust the upload destination (set it to None and keep
  the data local — `wpsecscan analytics show` is still useful for
  your own audit)

## Source-code review

The whole module is ~250 lines:
[`wpsecscan/analytics.py`](../wpsecscan/analytics.py).
Read it. Compare against this doc. If they diverge, file an issue.
