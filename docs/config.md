# Configuration files

WPSecScan stores all state under `~/.wpsecscan/` (override with
`WPSECSCAN_HOME=/some/path`).

## Files

| File | Purpose | Editable |
|------|---------|----------|
| `sites.json` | Persistent site list for weekly scans + creds | yes (use `wpsecscan sites`) |
| `disabled_checks.json` | Checks the user has switched off | yes (GUI grid) |
| `stars.json` | Starred finding IDs | yes |
| `searches.json` | Saved search filters | yes |
| `bounty_cache.json` | OSINT lookup cache (24h TTL; file name is literal) | auto |
| `owned_targets.json` | Hosts you may run `--aggressive` against (`{"hosts": [...]}`) | yes (use `wpsecscan owned`) |
| `ai_cost.json` | LLM cost log | auto |
| `perf_history.json` | Per-check duration samples | auto |
| `target_perf.json` | Per-target scan time samples | auto |
| `cache_trend.json` | Cache-hit-rate samples | auto |
| `fp_learner.sqlite` | AI false-positive learning DB | auto |
| `remediation_effectiveness.sqlite` | Remediation A/B store | auto |
| `merkle.log` | Hash-chained audit log | auto |
| `pci_evidence/<host>.json` | PCI evidence packs | auto |
| `plugins/*.py` | User-supplied custom checks | yes |
| `locales/<code>.json` | User-supplied translations | yes |

## Environment variables

| Var | Purpose |
|-----|---------|
| `WPSECSCAN_HOME` | Override config dir |
| `WPSECSCAN_NO_AI` | Hard-disable all AI features |
| `WPSECSCAN_QUIET` | Suppress sound effects |
| `WPSECSCAN_QUIET_START` / `_END` | Quiet hours range (default 22-7) |
| `WPSECSCAN_OPENAI_API_KEY` | OpenAI |
| `WPSECSCAN_ANTHROPIC_API_KEY` | Anthropic |
| `WPSECSCAN_OLLAMA_URL` | Ollama base URL |
| `WPSECSCAN_LLAMA_CPP_URL` | llama.cpp server URL |
| `WPSECSCAN_COMPLIANCE_FRAMEWORK` | Framework for the compliance-audit check (`hitrust`, `cmmc`, `nist_csf`, `cis_v8`, `iso_27001_2022`) |
| `WPSECSCAN_OWNED_TARGETS` | Hosts marked as owned for aggressive mode: comma-separated, `*.example.com` for subdomains, `1`/`true`/`*` for every target |
| `WPSECSCAN_PCI_EVIDENCE_DIR` | Override PCI evidence dir |
| `WPSECSCAN_DIGEST_EMAIL` | Where the weekly digest goes |
| `CF_API_TOKEN` | Cloudflare API (for WAF tuning) |

## Owned targets (aggressive-mode consent)

Aggressive checks run only against targets marked as owned; otherwise the
scan runs passive and the report carries an info finding (`consent_gate`).
There are three consent sources:

1. `--owned` on the command line (explicit; always wins).
2. `WPSECSCAN_OWNED_TARGETS` in the environment.
3. The owned-targets file, managed with `wpsecscan owned add <host>`,
   `wpsecscan owned remove <host>` and `wpsecscan owned list`.

### Daemon config (`wpsecscan --daemon config.yml`)

Each target entry can carry an `owned: true` key:

```yaml
targets:
  - url: https://shop.example.com
    schedule: "0 */6 * * *"
    aggressive: true
    owned: true        # you own / are authorised to test this host
```

`aggressive: true` without consent (no `owned: true`, no env variable, no
owned-targets entry) runs passive, and the daemon logs one warning per such
target at startup.

## Inspecting config

```
wpsecscan export-config              # effective merged config
wpsecscan config validate daemon.yml # lint a daemon YAML config
wpsecscan doctor                     # optional deps + tokens audit
```

Keep `~/.wpsecscan/` private: it can hold API tokens and the credentials vault.
