# CLI flag reference

`wpsecscan --help` is authoritative — this page is for browsing.

## Targets

| Flag | Purpose |
|------|---------|
| `--target URL` | Single site URL |
| `--target-file file.txt` | One URL per line |
| `--demo` | Built-in demo target (no network needed) |
| `--cidr 10.0.0.0/24` | Discover WordPress in a /24 (capped at 256 hosts) |

## Check selection

| Flag | Purpose |
|------|---------|
| `--only ID[,ID...]` | Only run these checks |
| `--skip ID[,ID...]` | Skip these checks |
| `--aggressive` | Enable aggressive (active-payload) checks |
| `--no-cve` | Skip CVE matching (faster) |
| `--deep-throttle` | Add the 20-minute deep-throttle mapping check |

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
| `--json PATH` | Custom JSON output path |
| `--html PATH` | Custom HTML output path |
| `--pdf PATH` | PDF report (needs `wpsecscan[pdf]`) |
| `--sbom PATH` | CycloneDX SBOM |
| `--quiet` | Suppress live progress (script-friendly) |

## Compliance

| Flag | Purpose |
|------|---------|
| `--compliance-framework F` | hitrust / cmmc / nist_csf / cis_v8 / iso_27001_2022 |
| `--pci-evidence` | Emit PCI 4.0 evidence pack |

## AI

All AI is opt-in via env vars (see [ai.md](ai.md)). Override:

| Flag | Purpose |
|------|---------|
| `--no-ai` | Same as `WPSECSCAN_NO_AI=1` |
| `--ai-summary` | Add LLM executive summary to report |

## Misc

| Flag | Purpose |
|------|---------|
| `--user-agent UA` | Override default UA |
| `--threads N` | Concurrent check workers (default 8) |
| `--profile` | cProfile the scan (writes `~/.wpsecscan/profile.prof`) |
| `--version` | Print version |

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| `wpsecscan sites add/list/remove/edit` | Manage the persistent site list |
| `wpsecscan schedule install/uninstall/pause/resume` | Weekly auto-scan |
| `wpsecscan digest configure/test` | Email digest setup |
| `wpsecscan ci-gate REPORT` | CI/CD failure gate |
| `wpsecscan submit --finding-id` | Build bug-bounty submission |
| `wpsecscan disclose --finding-id` | Coordinated disclosure email |
| `wpsecscan ai-cost` | LLM cost log |
