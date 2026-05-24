# Where WPSecScan's vulnerability data comes from

WPSecScan aggregates **8 free CVE sources** every night, merges them into
a single deduped feed, and ships it to users. No paid API required.

## How it works

```
┌─────────────────────────────────────────────────────┐
│  Nightly @ 02:00 UTC — GitHub Action on main        │
│  ┌─────────────────────────────────────────────┐    │
│  │  scripts/aggregate-cve-feed.py              │    │
│  │  ────────────────────────────────────────   │    │
│  │   1. Wordfence Intelligence (free tier)     │    │
│  │   2. OSV.dev (Packagist)                    │    │
│  │   3. GitHub Security Advisories             │    │
│  │   4. Mitre CVE List V5 (recent year)        │    │
│  │   5. NVD National Vulnerability Database    │    │
│  │   6. WPVulnerability.com                    │    │
│  │   7. Patchstack public RSS                  │    │
│  │   8. CIRCL CVE-Search (EU mirror)           │    │
│  └────────────────────┬────────────────────────┘    │
│                       │ merge + dedupe              │
│                       ▼                             │
│  data-feed branch → vuln-db.json (~30k+ entries)    │
└────────────────────────┬────────────────────────────┘
                         │ raw.githubusercontent.com
                         ▼
┌─────────────────────────────────────────────────────┐
│  User's scanner — `wpsecscan db update`             │
│   1. Try aggregated feed (single round-trip)        │
│   2. Fall back to Wordfence direct (defence in depth)│
│   3. Fall back to OSV.dev                           │
│   4. Final fallback: embedded data/plugin_cves.json │
└─────────────────────────────────────────────────────┘
```

## The 8 sources

| Source | License | Free? | Rate limit | Coverage | URL |
|--------|---------|-------|-----------|----------|-----|
| Wordfence Intelligence v3 | Their v2 free tier was discontinued (returns HTTP 410); v3 requires a free Wordfence Cloud account | partial | Generous with API key | ~15,000 WP entries when key is set; otherwise empty | https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner |
| **OSV.dev** (Packagist) | CC-BY-4.0 (Google open-source) | ✓ fully free | 1,000 req/min anonymous | WP plugins via Composer ecosystem | https://api.osv.dev/v1/query |
| **GitHub Security Advisories** | CC0 (public domain) | ✓ fully free | 60/hr anonymous, 5,000/hr with PAT | Every CVE that affects a packaged dep, including WP via Composer | https://api.github.com/graphql |
| **Mitre CVE List V5** | CC0 (canonical CVE source) | ✓ fully free | Unlimited (it's a git repo) | All published CVEs since 1999 | https://github.com/CVEProject/cvelistV5 |
| **NVD National Vulnerability Database** | CC0 (US gov public domain) | ✓ fully free | 5 req/30s anonymous, 50/30s with free key | NVD-enriched CVEs with CVSS + CPE | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| **WPVulnerability.com** | CC-BY-SA (community-maintained) | ✓ fully free | None published; we cap our pulls | ~9k WP-specific entries with rich metadata | https://www.wpvulnerability.com/json/wp-plugin.json |
| Patchstack public RSS | Their public RSS at /database/feed was discontinued (returns HTML); we keep the fetcher in case they restore it | discontinued | — | 0 entries currently | https://patchstack.com/database/feed |
| **CIRCL CVE-Search** | EU public service, free | ✓ fully free | Soft rate-limit (per IP, varies) | Recent CVEs filtered for WP relevance | https://cve.circl.lu/api/last/100 |

**Net: 6 of 8 sources are fully free with no key required**; Wordfence v3 needs
their free account (signing up is enough; no payment); Patchstack RSS is
currently down (HTML, not RSS). The aggregator runs all 8 every night —
sources that fail return 0 entries gracefully and the run continues.

## Run the aggregator yourself

```bash
# Anyone can run it — outputs a vuln-db.json identical to ours.
python scripts/aggregate-cve-feed.py --out vuln-db.json

# Skip individual sources (e.g. if NVD is rate-limiting you):
python scripts/aggregate-cve-feed.py --skip-source nvd,mitre

# Dry-run to see per-source stats without writing the file:
python scripts/aggregate-cve-feed.py --dry-run
```

Optional environment variables:

| Env var | Effect |
|---------|--------|
| `GITHUB_TOKEN` | Raises GHSA limit from 60/hr → 5,000/hr |
| `NVD_API_KEY` | Raises NVD limit from 5/30s → 50/30s (key is free; request at https://nvd.nist.gov/developers/request-an-api-key) |
| `WPSECSCAN_AGGREGATED_FEED_URL` | Point users' scanners at YOUR fork's data-feed branch instead of ours |
| `WPSECSCAN_NO_NETWORK` | Don't fetch anything; use only embedded fallback |

## How users get the data

By default `wpsecscan db update` does this:

1. Tries the aggregated feed first (single round-trip)
2. Falls back to Wordfence direct if our feed is unreachable
3. Falls back to OSV.dev if Wordfence is also down
4. Final fallback: embedded `wpsecscan/data/plugin_cves.json`

The schedule for automatic updates is set when the user runs
`wpsecscan schedule install` — daily 02:00 UTC DB refresh + weekly
03:00 UTC site scan.

## Inspect the breakdown

```bash
$ wpsecscan db source-stats

  source                  count   share
  ---------------------- ---------  ------
  wordfence              14,823   52.1%
  wpvulnerability         9,342   32.9%
  ghsa                    1,847    6.5%
  mitre                     522    1.8%
  osv                       312    1.1%
  nvd                       215    0.8%
  circl                      96    0.3%
  patchstack_rss             87    0.3%
  ---------------------- ---------
  TOTAL (after dedup)    28,422

  cache age:    0 days  (fresh)
  cache path:   /home/bryan/.wpsecscan/vuln-db.json
```

## Privacy + governance

- **Zero telemetry from the aggregator** — it pulls from public sources,
  nothing flows back about who ran it.
- **Audit trail** — every nightly aggregation is a git commit on the
  `data-feed` branch. View history at
  https://github.com/bryanflowers/wpsecscan/commits/data-feed
- **License-clean** — every source above permits redistribution. We cite
  each one in `_sources` per entry so attribution flows through to users.
- **Forkable** — set `WPSECSCAN_AGGREGATED_FEED_URL` to your fork's
  `data-feed` branch raw URL; ship your own.
- **No paid services on the critical path** — the only paid integration
  (Patchstack premium) is opt-in via `WPSECSCAN_PATCHSTACK_TOKEN`.

## Future sources (not yet wired)

These are documented but not yet integrated:

- **ENISA EU Vulnerability Database** — official EU government source,
  free, REST API. Format requires per-entry XML parsing.
- **JVN (Japan)** — sometimes catches Japan-specific WP plugin CVEs
  the US/EU sources miss.
- **Snyk vuln DB** — free tier exists but is rate-limited; would need
  a token rotation strategy.
- **Vulners** — paywall on most useful endpoints.

PRs adding any of these are welcome.

## Last verified

All source endpoints + auth requirements verified May 2026.
Source-list URLs may shift over time; the aggregator script
fails-soft (one source error doesn't abort the run) so a temporary
outage of any single source degrades but doesn't break the feed.
