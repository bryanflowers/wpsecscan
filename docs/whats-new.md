# What's new

Quick-scan version highlights for upgrading users. Full detail lives
in [CHANGELOG.md](../CHANGELOG.md).

## v2.8.2 (current)

**Hotfix + dead-code cleanup release.**

- **Two regressions fixed**: the v2.8.1 CI progress-callback signature
  was reversed (dots never fired in non-TTY runs); the new `--output`
  alias made `--out` ambiguous via argparse abbreviation. Upgrade if
  you use either.
- **3 new CLI subcommand families** wire the previously-dead v28
  modules to real CLI surface:
  - `wpsecscan emit <FORMAT> <REPORT.json>` — 14 formats including
    SPDX SBOM, in-toto, CEF, LEEF, CAB, risk-CSV, HIPAA / FedRAMP /
    Cyber Essentials Plus / Essential 8 mappings.
  - `wpsecscan push <PROVIDER> <REPORT.json>` — 13 destinations:
    GitLab CI, CircleCI, Azure DevOps, Buildkite, Shortcut, Plane,
    Wiz/Lacework, chat (Mattermost/RocketChat/Telegram), managed-host
    events, n8n/Make.com/Notion.
  - `wpsecscan ai <SUB>` — 6 AI helpers (remediation, plan,
    visual-diff, injection-check, drift, control-map).
- **`wpsecscan check list --json`** — machine-readable check
  inventory with OWASP/ATT&CK tags. Power CI gates and dashboards.
- **`WPSECSCAN_OUT_DIR`** env var alongside `--out` for CI artifact
  centralisation.
- **`--md-frontmatter`** — Markdown reports gain YAML front-matter for
  Hugo / Obsidian / MkDocs.
- **SARIF deterministic ordering** — `git diff` of report files is
  now meaningful in CI.
- **Confirmation prompts** on `creds rm <site>` (bulk) and
  `snooze clear <url>` to prevent accidental data loss.
- **Webhook HTTPS-only** by default — `wpsecscan push` refuses plain
  HTTP destinations unless `WPSECSCAN_ALLOW_INSECURE_WEBHOOK=1`.
- **+75 tests** (930 → 1005) covering the v2.8.1 dead-code gap.

## v2.8.1

- 17 new defensive WP/WC security checks (F2-F23): cart-abandonment
  XSS, draft-order escalation, payment-link replay, Stripe Connect
  state CSRF, plugin update-server integrity, ActivityPub leaks, FSE
  global-styles, multisite IDOR/RBAC, REST-only admin, Next.js secret
  leaks, AI-agent tool injection, WC multi-vendor IDOR, WebAuthn
  RP-ID, WC refund-flow IDOR.
- 13 new integrations, 11 AI helpers, 16 compliance/enterprise
  features — see CHANGELOG.
- Grouped `--help`, `--resume`, `--self-update`, fish completion,
  batch ETA, CI progress fallback.

## v2.8.0

- Largest release in project history: 57 fixes/additions including 46
  bugs, 5 features (WC coupon-enum, headless CORS lockdown, Trusted
  Types CSP, 5-tier smart-explain, interactive HTML dashboard with
  filter+search), 8 UX wins.

## v2.7.x

- v2.7.3 ZAP/Wapiti exports; PyPI Trusted Publishing validated.
- v2.7.2 Two mega-audit-driven bug-fix waves.
- v2.7.1 Hot-fix release.
- v2.7.0 (~H95-H109): Vault/1Password integration, Snyk import,
  HackerOne template, VirusTotal/urlscan enrichment, MSFT Sentinel
  KQL, AWS Security Hub, GCP SCC, PagerDuty AIOps, statuspage,
  Linear/Asana/ClickUp/Monday push, Teams reaction snooze.

## Upgrading

```bash
pip install --upgrade wpsecscan
# Or use the new --self-update flag:
wpsecscan --self-update
```
