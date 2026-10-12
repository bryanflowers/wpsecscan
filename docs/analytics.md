# Usage analytics — local, opt-in, nothing uploaded

WPSecScan has a small opt-in module (`wpsecscan/analytics.py`) that can
record which features get used. It is built around two properties:

1. **Default off.** Nothing is recorded until you explicitly run
   `wpsecscan analytics enable` (or tick the box in the GUI).
2. **Local only.** Events are written to a file on your machine. No shipped
   command or code path uploads them anywhere, and the project operates no
   analytics endpoint.

## Opting in

```bash
wpsecscan analytics enable
```

`enable` takes no destination argument. Or in the GUI: `Tools → Analytics options...`

## Inspecting what is recorded

```bash
wpsecscan analytics show           # last 50 events
wpsecscan analytics show 500       # last 500 events
wpsecscan analytics export ./my-events.jsonl
```

Events live in `~/.wpsecscan/analytics/events.jsonl` (JSON lines,
human-readable; the file rolls over at 10 MB and keeps a few old copies).

## What the module records (when enabled)

| Event | Fields |
|-------|--------|
| `cli_command`   | subcommand, duration_ms, exit_status |
| `check_ran`     | check_id, duration_ms, finding_count_bucket |
| `gui_action`    | action_name, duration_ms |
| `feature_used`  | feature_name |
| `report_export` | format, finding_count_bucket |

Each entry also carries a timestamp rounded to the minute, the WPSecScan
version and the anonymous ID. Finding counts are bucketed (`0` / `1-5` /
`6-25` / `26-100` / `101-500` / `500+`).

The recording function has an **allowlist** of fields per event type; any
other field passed to it is dropped. It is not designed to accept target
URLs, finding titles or evidence, site config, or API keys.

## Anonymous ID

A random UUID stored at `~/.wpsecscan/analytics/anonymous_id.txt`. It is
regenerated at the start of each calendar quarter, and is not derived from
hostname, IP or username.

## Forget me

```bash
wpsecscan analytics forget
```

Deletes the local event logs (including rolled-over copies) and the
anonymous ID.

## Disabling

```bash
wpsecscan analytics disable
```

Stops recording. Existing local data is preserved; use `forget` to delete it.

## Status

```bash
wpsecscan analytics status
```

Shows enabled / disabled, anonymous ID, event count and storage path.

## Source-code review

The module is [`wpsecscan/analytics.py`](../wpsecscan/analytics.py). Read it
and compare against this page; if they diverge, file an issue.
