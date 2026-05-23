# Changelog

All notable changes to WPSecScan are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (BREAKING for end users)
- **GUI binary renamed**: `wordpress-barebacker.exe` → `wpsecscan-gui.exe`.
  CLI binary stays as `wpsecscan.exe`. Matches `git`/`git-gui`,
  `python`/`pythonw` conventions. The old binary name is removed from
  `build.ps1`, `pyproject.toml`'s `[project.gui-scripts]`, the CI
  workflow, Defender-exclusion script, code-signing docs, dependencies
  docs, completion script, and every README / `.md` reference.
- **Human-facing app name unified**: `Wordpress Barebacker` → `WPSecScan`
  everywhere — GUI window title, dialog headers, batch dashboard,
  version-info `ProductName`, README title.

### Added
- GitHub-compliance files: LICENSE (MIT), SECURITY.md, CONTRIBUTING.md,
  CODE_OF_CONDUCT.md, CODEOWNERS, issue + PR templates, tests workflow,
  pyproject.toml, DEPENDENCIES.md, this CHANGELOG, Dependabot config.
- README authorised-use banner + status badges.

### Fixed
- White-on-white hover tooltips for `ttk.Checkbutton` / `ttk.Radiobutton`
  (Aggressive mode / Extract read-only proof / Deep throttle mapping).

---

## [1.5.0] — 2026-05-23 — Round-56 "see it all working"

### Added
- **Activity event bus** (`wpsecscan/activity.py`) with 25 emit sites
  across threat-intel, integrations, reporters, governance, meta,
  artifact categories.
- **Live multi-panel console dashboard** (`wpsecscan/console_live.py`) —
  `rich.Live` layout shown during scans, with streaming findings + activity
  feed + progress footer.
- **End-of-scan "What ran" stats panel** in the console reporter.
- **GUI Activity tab** — right-side detail pane wrapped in a `ttk.Notebook`,
  Activity tab streams bus events with category-coloured badges, auto-scroll,
  200-line cap, subscriber cleanly unregisters on window close.
- **`--demo` flag** — synthetic scan with ~30 findings + ~25 activity
  events; writes every reporter's output to `~/.wpsecscan/demo/`. Tools →
  Demo mode in the GUI.
- **`--no-live` flag** — disables the live dashboard, falls back to the
  static reporter (useful for CI logs).
- **JSON reports embed `activity_log`** — full timeline from the bus.

### Fixed (round-56 QA pass)
- `console_live.py`: replaced internal `Progress.get_renderables()` call
  with the public renderable path.
- `gui.py`: activity subscriber now unregisters on `WM_DELETE_WINDOW`
  (was a memory leak holding a destroyed Tk callback).
- `gui.py`: Activity-tab line trim off-by-one (was leaving 201 lines).

### Tests
358 pass (was 340).

---

## [1.4.0] — 2026-05-23 — Round-55 (waves A-H, 47 features)

### Added
- **10 new checks**: `cloud_metadata_ssrf`, `dns_rebinding`, `hpp`,
  `backup_file_fuzz`, `hostname_collision`, `header_smuggling_case`,
  `http3_fingerprint`, `session_fixation`, `csrf_entropy`, `plugin_route_fuzz`.
- **References database** (`data/references.json`) — per-check_id
  OWASP / PortSwigger / HackTricks / video links.
- **Screenshot capture** (`screenshot.py`) — Playwright captures crit/high
  findings, embeds as base64 in HTML report.
- **Issue exporters** (`reporters/issue_export.py`) — Jira / Linear / GH
  Issues curl-script generators.
- **User-tunable severity weights** (`risk_weights.py`).
- **Compliance gap matrix** (`compliance_gap.py`).
- **Light + dark + color-blind palette** toggles in HTML report.
- **Auto-update channel** (`auto_update.py`) — daily GH-releases check.
- **Self-healing + budget tracker** (`check_health.py`).
- **Crash auto-submit** helper (`crash_submit.py`) with secret redaction.
- **SBOM emission** (`sbom.py`) — CycloneDX 1.5 via `--sbom`.
- **Incremental scan** (`incremental.py`) — `--since YYYY-MM-DD` skips
  low-churn checks if target hasn't changed.
- **Per-host learned baseline** for anomaly detection.
- **Redis CVE-DB cache** (`redis_cache.py`) — opt-in via env.
- **OpenTelemetry traces** (`otel.py`) — opt-in via env.
- **GraphQL-style report query** (`report_query.py`) — `--query EXPR`.
- **Hot-reload checks** (`hot_reload.py`).
- **Plugin scaffold generator** (`plugin_scaffold.py`).
- **HTTP API server** (`api_server.py`) — stdlib http.server, 5 endpoints
  + `/openapi.json`, bearer auth, RBAC, path-traversal guard.
- **Org dashboard reporter** (`reporters/org_dashboard.py`).
- **RBAC** (`rbac.py`) — bcrypt + sha256 fallback, default-deny.
- **Audit-log shipping** (`audit_log_ship.py`) — Splunk HEC / Datadog / Loki.
- **Slack + Discord chat bots** (`chat_bot.py`).
- **Per-region egress** (`region_egress.py`) — `--region` + proxy env.
- **Customer-facing attestation PDF** (`reporters/attestation.py`).
- **Auto-PR fix script** (`auto_pr.py`) — `--auto-pr --auto-pr-repo`.
- **Fix-feedback store** (`fix_feedback.py`).
- **Trend markdown export** (`trend_md.py`).
- **Shell completion generator** (`completion.py`) — bash / zsh / pwsh.
- **i18n wiring into GUI** (English + Spanish, View → Language).
- **Onboarding wizard** (`gui_windows.open_onboarding_wizard`) on first run.

### Fixed (round-55 + round-55-QA passes — 10 + 6 bugs total)
- Cookie-domain boundary regex in `subdomains.py` (false-positive on
  lookalike apex strings).
- JWT cracked-secret no longer duplicated into `Finding.extra`.
- CISA KEV cache resilient to `{"cves": null}`.
- Cron parser raises on out-of-range values (was silently never firing).
- `exec_pdf.py` fallback always rewrites to `.html`.
- `subdomains.py` cookie regex tightened.
- API-server bearer comparison switched to `hmac.compare_digest`.
- API-server `_TASKS` capped at 1000 with LRU eviction.
- API-server path-traversal guard now rejects `\\`, `\x00`, urlencoded
  slashes, and any name failing `Path(name).name` round-trip.
- `rbac.has_permission` default-denies unknown roles instead of raising.
- `audit_log_ship.py` protocol-detection order (Datadog before Loki) +
  `import time` at top.
- `gui_windows.py` `APP_NAME` defined (was crashing onboarding wizard).
- `report_query.py` `~` regex operator (`\b~\b` never matched).
- `otel.py` retries init if env appears after first call.
- `completion.py` FLAGS list synced with argparse.
- `--since` incremental flag wired into scanner.
- `check_health.reset_run()` called between batch scans.
- `record_duration` skipped when check raised (kept baseline clean).
- Onboarding wizard auto-shown on first run.
- `risk.py` `if weights is not None:` guard for corrupted weights file.
- `--completion` moved before `logmod.configure` so piped output isn't
  contaminated.

### Tests
340 pass (was 281).

---

## [1.3.0] — 2026-05-23 — Round-54 (A1-G4, 54 features)

### Added
- **14 new checks**: `webdav`, `dev_params`, `abuseipdb_lookup`,
  `jwt_audit`, `ssti`, `nosql_injection`, `s3_bucket_discovery`,
  `github_leak_search`, `path_bypass`, `race_condition`, `waf_ruleset`,
  `oauth_oidc`, `saml_xsw`, `dom_xss_headless` (Playwright optional).
- **Threat-intel integrations**: CISA KEV, EPSS, VirusTotal, Sucuri
  SiteCheck, NVD/Wordfence CVE explainer.
- **Per-check `cwe` + `d3fend` tag fields**.
- **Reporters**: `exec_pdf.py` (reportlab or HTML fallback),
  `diff_viewer.py` (standalone HTML), `burp_export.py` (Burp scope XML),
  SVG severity × OWASP heatmap embedded in HTML report.
- **CLI flags**: `--fail-on`, `--abuseipdb-token`, `--vt-token`,
  `--github-search-token`, `--diff-against`, `--shell`, `--burp-export`,
  `--exec-pdf`, `--replay-har`, `--daemon`.
- **GUI windows**: playbook walker (E3), drill-by-tag (E7), multi-URL
  trend (E8), tutorial (E10), marketplace browser (F5), assign-owner +
  comments (G1/G2).
- **Infra**: GitHub Actions workflow template, GitLab CI / Jenkins / Azure
  DevOps templates, Dockerfile + docker-compose.yml, SDK.md,
  DISTRIBUTED-SCAN.md.
- **Audit log JSONL** (`audit_log.py`).
- **i18n stub** (`i18n.py`) — English + Spanish.
- **HAR replay** (`har_replay.py`).
- **Custom signature / payload drop-ins** in `~/.wpsecscan/{signatures,payloads}/`.

### Fixed (round-54 QA pass — 5 bugs)
- `subdomains.py` cookie-domain false-positive.
- `jwt_audit.py` cracked secret in `extra` removed.
- `cisa_kev.py` `set(None)` TypeError.
- `daemon.py` cron parser out-of-range silent failure.
- `exec_pdf.py` fallback extension handling.

### Tests
281 pass (was 260).

---

## [1.0.0 – 1.2.x]

Earlier rounds built the baseline 80 checks, exploit playbooks, risk
scoring, CSV/SARIF/JSON/HTML reporters, multi-target + dashboard,
deep-throttle login mapping, scheduled scans, GitHub Issues integration,
Defender false-positive mitigations (fragment-concatenated obfuscation +
bundled exclusion script + first-run dialog), and the two-binary
PyInstaller build.

---

## Versioning policy

- **MAJOR** — breaking changes to CLI flags, JSON schema, GUI file
  locations, or removed checks
- **MINOR** — new checks, new flags, new reporters (additive)
- **PATCH** — bug fixes, test additions, doc improvements

Release notes for each tag live both here and on the GitHub Releases page.
