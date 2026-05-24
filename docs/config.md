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
| `bounty_cache.json` | OSINT cache (24h TTL) | auto |
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
| `WPSECSCAN_COMPLIANCE_FRAMEWORK` | Same as `--compliance-framework` |
| `WPSECSCAN_PCI_EVIDENCE_DIR` | Override PCI evidence dir |
| `WPSECSCAN_DIGEST_EMAIL` | Where the weekly digest goes |
| `CF_API_TOKEN` | Cloudflare API (for WAF tuning) |

## Permissions audit

```
wpsecscan check-config
```

Walks `~/.wpsecscan/`, warns about world-readable secrets, broken symlinks,
and oversized cache files.
