# CLI flag reference

`wpsecscan --help` is authoritative — this page is for browsing.

## Targets

| Flag | Purpose |
|------|---------|
| `URL` (positional) | Single site URL, e.g. `wpsecscan https://yoursite.com` |
| `--file FILE` | One URL per line (`#` comments OK) |
| `--demo` | Synthetic scan against a fake target (no network needed) |
| `--dry-run` | List the checks that would run, then exit (no HTTP requests) |

## Check selection

| Flag | Purpose |
|------|---------|
| `--aggressive` | Enable aggressive (active-payload) checks. They run passive unless the target is marked as owned (below) |
| `--owned` | Mark this target as owned / authorised for this run |
| `--prove` | For each confirmed aggressive finding, run a read-only proof helper (needs `--aggressive`) |
| `--deep-throttle` | Add the deep login-throttle mapping check |
| `wpsecscan only CHECK_ID URL` | Run just one check against a URL |
| `wpsecscan check disable ID` / `enable ID` | Persistently skip / re-enable a check |
| `wpsecscan check list [--json]` | List the check inventory |

### Owned targets

Aggressive mode runs passive unless the target is marked as owned. Three
ways to mark it, in precedence order: `--owned` on the command line, the
`WPSECSCAN_OWNED_TARGETS` environment variable (comma-separated hosts,
`*.example.com` for subdomains), or the owned-targets list managed with
`wpsecscan owned add <host>` / `remove` / `list`.

## Auth

| Flag | Purpose |
|------|---------|
| `--auth-user U` | Username for authenticated scan |
| `--auth-pass P` | Password (cookie-login flow) |
| `--auth-app-password P` | WP Application Password (preferred) |
| `--auth-totp CODE` | TOTP if 2FA enabled |
| `--companion-token T` | Use the WP companion plugin token |

## Output

| Flag | Purpose |
|------|---------|
| `--out PATH` | Output directory or filename stem (default: current directory) |
| `--format F[,F...]` / `--output` | `json`, `html`, `csv`, `md`, `xlsx`, `sarif`, `burp`, `docx`, `exec-pdf` |
| `--json-only` / `--html-only` | Write only the JSON or only the HTML report |
| `--csv`, `--sarif`, `--md`, `--xlsx` | Also write that format |
| `--burp-export`, `--exec-pdf`, `--docx` | Burp scope XML, one-page executive PDF, Word report |
| `--sbom OUT.json` | Write a CycloneDX SBOM and exit (no scan) |
| `--quiet` | Suppress console output (still writes report files) |

`wpsecscan emit FORMAT REPORT.json` writes 14 more export formats from a
saved JSON report.

## Compliance

Compliance mappings are in the JSON/HTML report automatically. To use a
framework lens, set `WPSECSCAN_COMPLIANCE_FRAMEWORK` (`hitrust`, `cmmc`,
`nist_csf`, `cis_v8`, `iso_27001_2022`), or run a single-framework gap
analysis with `wpsecscan compliance audit URL --framework F`. See
[compliance.md](compliance.md).

## AI

All AI is opt-in via env vars (see [ai.md](ai.md)). Override:

| Setting | Purpose |
|---------|---------|
| `WPSECSCAN_NO_AI=1` | Hard-disable all AI features |
| `--tldr`, `--ai-explain-for AUDIENCE` | LLM-written summaries in the report |

## CI gating

| Flag | Purpose |
|------|---------|
| `--fail-on LEVEL[,LEVEL]` | Exit with code 2 if any finding is at or above this severity |
| `--baseline BASELINE.json` | Print NEW / RESOLVED findings against a saved report |

## Misc

| Flag | Purpose |
|------|---------|
| `--user-agent UA` | Override default UA |
| `--concurrency N` | Concurrent requests per host (default 10) |
| `--timeout SECONDS` | Per-request timeout (default 15) |
| `--profile NAME` | Load a named profile saved via the GUI or `wpsecscan profile save` |
| `--debug` | Verbose internal logging to `~/.wpsecscan/logs/` |
| `--version` | Print version |

## Subcommands

`wpsecscan --help` lists every subcommand. Common ones:

| Subcommand | Purpose |
|------------|---------|
| `wpsecscan sites add/list/scan/remove` | Manage the persistent site list |
| `wpsecscan schedule install/uninstall` | Weekly auto-scan |
| `wpsecscan digest ...` | Email / webhook digest setup |
| `wpsecscan owned add/remove/list` | Manage the owned-targets list |
| `wpsecscan push PROVIDER REPORT.json` | Push a saved report to one of 16 providers |
| `wpsecscan ai SUB ...` | AI helpers (7) |
| `wpsecscan ai-cost` | LLM cost log |
