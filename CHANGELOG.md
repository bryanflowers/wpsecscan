# Changelog

All notable changes to WPSecScan are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Rolled to v2.9.0 via the v2.8.4 stuck-rule:
- **GUI M10/M11/L1/L4/L5/L9** — Tk-interactive polish items (mkdir
  blocking, mark_wizard_seen ordering, Windows ACL via icacls, trend
  rename fallback, proxy lock during scan, background report writes).
- **Branch protection on `main`** — needs admin click in repo settings.
- **9 Dependabot PRs** (#10–#18) — pre-existing CI failures on Python
  3.10/3.11 need triage independent of release flow.

Plus the v2.8.3 / v2.8.2 carry-overs.

## [v2.8.4] — 2026-06-10

GUI-focused quality + UX release. **2 Critical bugs**, **7 High**,
**12 Medium/Low**, **10 UX wins**, **GUI surface for the v2.8.x
emit/push/ai subcommand families** (the biggest UX gap), **mobile
PWA** improvements, **+31 tests** (1066 → 1097), repo ops hygiene.

### Phase 1 — Critical + High GUI bugs

- **C1** gui.py: `quick_btn` + `cancel_btn` shared grid column 3, so
  the Quick button was invisible during every scan. Each toolbar
  button now owns its own column; downstream columns shifted right.
- **C2** gui_windows._mt_worker: fired `after()` callbacks on the
  multi-target Treeview after it could be destroyed. Wrapped every
  callback in `_safe_after` guarded by `win.winfo_exists()`.
- **H1** gui._save_pref: non-atomic write could corrupt `prefs.json`
  when the 800ms debounced geometry handler raced a theme save.
  Now uses `reporters._atomic_write_text` + `threading.Lock`.
- **H2** gui: filter state vars (`show_*_var`, `search_var`) are now
  loaded from + saved to prefs.json — "critical+high only" survives
  restart.
- **H3** scanner.scan() + gui._run_scan: `patchstack_token` was
  collected by the onboarding wizard but silently ignored. Added the
  kwarg + ctx entry + wired through `_run_scan`.
- **H4** gui._on_quick_scan_click: 500ms `after()` timer for
  restoring aggressive/prove vars fired unconditionally (clobbering
  user state on URL-invalid early return) and two Quick clicks within
  500ms raced. Replaced with `_restore_quick_scan_state()` called
  from `_handle_done`/`_handle_error`/early-return.
- **H5** gui._on_window_close: now joins the scan thread with
  `timeout=2.0` before `root.destroy()`. Pre-fix exit-during-scan
  raised `RuntimeError: main thread is not in main loop`.
- **H6** gui_windows.open_multitarget: removed duplicate `<Destroy>`
  binding.
- **H7** mobile_api: `_send_json` / `_send_text` now emit CORS
  headers (Allow-Origin/Headers/Methods); new `_send_404` helper has
  explicit `Content-Length: 0`. Configurable via
  `WPSECSCAN_MOBILE_API_CORS_ORIGIN` env var (default `*`).

### Phase 2 — 12 Medium + Low GUI bugs

- M2 changelog viewer + tutorial singleton guards
- M3 `_open_html` shows toast when file is missing (was silent no-op)
- M4 `_open_out_folder` cross-platform (`os.startfile` on Windows,
  `open` on macOS, `xdg-open` on Linux)
- M5 `OnboardingTour._dismiss` TclError guard
- M7 reports saved to `~/.wpsecscan/reports` instead of `Path.cwd()`
- M8 `open_playbook_walker` singleton per check_id
- M9 `_append_activity` defensive int parse
- L2 `_Tooltip._show`/`_hide` TclError guards
- L3 `open_history_search` removed duplicate KeyRelease+trace_add
- L6 PHP companion `test_connection_ajax` saves/restores operator's
  prepared token (was silently destroying it on cleanup)
- L7 "Schedule recurring scan…" Tools menu hidden on non-Windows
- L8 `_populate_tree` implemented (previously called behind
  `hasattr` and silently did nothing — "Open saved report" loaded
  data into `_current_report` but never repainted the tree)

### Phase 3 — 10 UX wins

- **U#1** Ctrl+F focuses the search/filter Entry
- **U#2** Ctrl+R triggers Re-scan
- **U#3** F1 opens context-sensitive docs
- **U#4** Alt+D triggers Diff with last
- **U#8** Panedwindow sash position persisted to prefs.json
- **U#9** Findings tree changed to `selectmode="extended"` for
  multi-select bulk actions
- **U#14** New "Copy CLI" toolbar button
- **U#16** New "★ Star" toolbar button — copies JSON+HTML to
  `~/.wpsecscan/starred/` so it's never pruned
- **U#19** Tooltips on Aggressive + Prove checkboxes
- **U#20** Help menu surfaces the existing changelog viewer

### Phase 4 — GUI surface for v2.8.x subcommand families

The biggest UX gap closed: 14 emit formats + 16 push providers + 7 AI
helpers were CLI-only. Now surfaced in the desktop GUI:

- Context-menu: "Get AI remediation plan", "Generate WAF rule
  (Cloudflare)", "Generate WAF rule (ModSecurity)"
- File → "Export As…" submenu: 14 entries
- File → "Push to…" submenu: 16 entries

All callbacks run in a background thread + toast on success/failure.

### Phase 5 — Mobile PWA improvements

- **P1** `POST /api/scan` endpoint (token-gated)
- **P2** `GET /api/report/<host>/findings/<idx>` per-finding detail
- **P4** `do_OPTIONS` CORS preflight handler
- **P3** Tools → "Start mobile companion server…" with QR-code launcher

### Phase 6 — Test coverage (+31 tests, 1066 → 1097)

- 21 regression tests for Phase 1 bugs + Phase 3 UX + Phase 4 dispatch
- 10 mobile_api endpoint tests (CORS, OPTIONS, POST /scan, per-finding)

### Phase 7 — Repo ops hygiene

- Created missing GitHub labels `automated` + `ci`
- New `.github/workflows/codeql.yml` — Python SAST closing the
  Scorecard SAST: 0 → 10 gap

1097 tests pass.

## [v2.8.3] — 2026-06-01

Bug-fix + dead-code-cleanup + test-coverage-boost + feature-batch
release. ~40 distinct fixes/improvements across 6 phases. 1066 tests
pass (was 1005 at v2.8.2 → +61 new tests).

### Phase 1 — Critical & high-impact bugs

- **C1** wp-plugin/wpsecscan-companion/includes/rest.php: wrap all 5
  `SHOW TABLES LIKE '{$var}'` sites in `$wpdb->prepare(...)`. Sets
  the correct pattern so neighboring devs don't copy bare
  interpolation into user-tainted contexts.
- **H1** checks/cache_poisoning.py: operator-precedence bug — the
  v2.8.2 expression evaluated `and` before `or`, so the `no-store`
  guard only applied to the `max-age` sub-clause. A response with
  `Cache-Control: public, no-store` was wrongly classified
  cacheable and emitted a false high-severity finding. Parenthesised.
- **H2** api_server.py: `_history_for()` glob was too greedy
  (`*{safe}*.json` matched files whose name merely contained the
  target's safe-filename). Switched to `glob.escape(safe) + "-*.json"`
  (prefix-anchored, mirrors `history.snapshot_history`).
- **H3 + H4** reporters/*.py: 24 reporters bypassed the v2.8.1
  `_atomic_write_text` helper despite the helper being introduced
  for this. Migrated badge_svg, csv_out, compliance_attestation,
  burp_export, board_one_pager, diff_viewer, diff_agency,
  gdpr_dsr_report, finding_heatmap, org_dashboard, issue_export,
  executive_pack, executive_tldr, share_link, public_page,
  vex_export, snapshot_compare, user_template, dashboard,
  xlsx_pivot, attestation, auditor_pdf, d3fend_mapping, docx_report,
  exec_pdf — all now use `_atomic_write_text`.
- **H5** gui.py:1283: `_drain_queue` rescheduled `after(40, ...)`
  without a `winfo_exists` guard. Closing the GUI mid-scan fired
  the callback on a destroyed widget → unhandled `TclError`. Added.
- **M3** _util.py: `save_versioned_json` now cleans up its temp file
  on write failure (matches `reporters._atomic_write_text`).
- **M5** checks/debug_leaks.py: removed `or weird.status_code == 500`
  from the outer trigger; bare 500s without PHP markers no longer
  emit a medium-severity finding with empty evidence.
- **L9** wp-plugin/wpsecscan-companion/includes/admin.php: admin
  AJAX fetch now includes `_wpnonce` so `check_ajax_referer`
  actually validates (was silently failing pre-fix).
- **wpsecscan.yml** workflow template: bumped pinned version from
  `==2.7.3` (4 minors stale) to `>=2.8.3,<3` so users of the
  drop-in scan template auto-track latest 2.x.

### Phase 2 — Dead-code cleanup

- Deleted `wpsecscan/licensing.py` — zero importers, never wired up.
  The companion v14 PHP plugin handles licensing server-side.

### Phase 3 — Test coverage (+61 tests, 1005 → 1066)

- `tests/test_v283_check_coverage.py` (33 tests) — happy-path +
  edge-case for cache_headers, csrf_nonce, debug_leaks (incl. M5
  regression), error_pages, interactivity_api_state_leak,
  mcp_endpoint_exposure, mixed_content, security_txt,
  wp_cron_disabled, app_passwords, core_cves; parametrised
  empty-response matrix across all 20 high-impact untested checks.
- `tests/test_v283_reporter_coverage.py` (15 tests) — render+write
  round-trip for compliance_attestation, vex_export, gdpr_dsr_report,
  auditor_pdf, burp_export, finding_heatmap, executive_tldr,
  d3fend_mapping.
- `tests/test_v283_phase1_regressions.py` (7 tests) — H1/H2/H5/M5/C1
  regression guards + reporter atomic-write source-level guard.
- `tests/test_v283_cli_dispatch.py` (6 tests) — smoke for
  _cmd_annotate, _cmd_verify_release, _cmd_ai_options, _cmd_ai_cost,
  _cmd_doctor exit-code semantics + SUBCOMMAND_NAMES sanity.

### Phase 4 — UX quick wins (9 shipped; U#9 splash → v2.9.0)

CLI:
- **U#1** `wpsecscan init` — interactive first-run wizard.
- **U#2** `wpsecscan check disable/enable <ID>` subcommands.
- **U#3** `wpsecscan compare-pypi-version` — passive staleness check.
- **U#4** `wpsecscan export-config` — JSON/YAML dump of effective
  merged config (redacts TOKEN/KEY/SECRET/PASS env values).
- **U#5** `wpsecscan benchmark <URL>` — per-check timing table.
- **U#6** SOCKS5 proxy fix in http.py — prefers httpx-socks, falls
  back to httpx native socksio; raises clear ImportError when
  neither is installed.

GUI:
- **U#7** "Quick" toolbar button next to "Scan" — passive-only fast
  scan with one click.
- **U#8** Inline severity legend (5 color chips) below the findings
  Treeview.

Reporter:
- **U#10** `--single-page-html` flag — injects print-friendly CSS
  overrides (no sticky nav, page-break-inside avoidance) so browser
  PDF export produces clean pagination.

### Phase 5 — 5 new checks + 3 new integrations + 1 AI helper

Checks (F66-F70):
- F66 `interactivity_api_directive_xss` — WP 6.5+ Interactivity
  API directive-XSS reflection probe.
- F67 `wc_stores_api_rate_limit_oracle` — 5-burst cart-add timing
  probe.
- F68 `wc_hpos_namespace_drift` — HPOS detection + dual-path
  permission-check advisory.
- F69 `cookie_banner_cosmetic_vs_blocking` — vanilla-vs-reject probe
  to distinguish blocking from cosmetic cookie banners.
- F70 `plugin_slug_squat_check` — wp.org `author` field drift
  detection across scans (supply-chain attack pattern).

Integrations (I14-I16, surfaced via `wpsecscan push`):
- I14 `sentry_release_correlation` — Sentry Releases API.
- I15 `datadog_incident_create` — auto-create incident on critical
  findings.
- I16 `defectdojo_push` — SARIF import via /api/v2/import-scan/.

AI helper (F71, surfaced via `wpsecscan ai waf-rule`):
- F71 `generate_waf_rule_for_finding` — LLM-generated Cloudflare
  Expression Language or ModSecurity SecRule for findings not in
  the pre-authored `waf_rules.py` dictionary.

### Phase 6 — docs + dev experience + CI

- README badge: 1005 → 1066 passing tests.
- README: new "v2.8.x subcommand families" section with 11
  representative examples.
- pyproject.toml: added `Programming Language :: Python :: 3.13`
  classifier.
- New `Justfile`: test/test-fast/test-k/lint/build/build-exe/run/
  gui/quick recipes.
- New `.pre-commit-config.yaml`: ruff E/W/F/UP/B/I + pre-commit-hooks
  basics + JSON lint on data/.

1066 tests pass.

### Deferred from v2.8.3 to v2.9.0

- **GUI U#11** (tree empty-state callout) — Treeview empty-state
  painting is non-trivial in Tk; deferred.
- **GUI U#13** (open prior HTML report from scan-history rows) —
  cross-window action wiring deferred.
- **Phase 2.5** wire `json_migrations.load_versioned` into the 3 real
  callers (cli_extras.py, mobile_v27.py) — existing callers use
  `load_home_json` with a different shape; full refactor scoped to v2.9.0.

Plus the v2.8.1 carryovers (still applicable; see v2.8.1's tail).

## [v2.8.2] — 2026-05-31

Hotfix + dead-code-cleanup release. Fixes two regressions introduced
in v2.8.1, wires the previously-unreachable v28 modules into real CLI
surface, and lands 11 UX polish wins.

### Critical regressions fixed (C1 + C2)

- **C1** — `__main__._ci_on_progress` parameter order didn't match
  `scanner.ProgressCallback` (event, check_id, check_name, result).
  The v2.8.1 signature was reversed, so the `status == "done"` branch
  never fired and CI dot-fallback was silently broken. Upgrade if you
  run scans in non-TTY environments.
- **C2** — `ArgumentParser(allow_abbrev=False)` resolves the
  ambiguity between `--out` and the new `--output` alias added in
  v2.8.1. Every v2.8.1 invocation that used `--out` raised
  `argparse.ArgumentError: ambiguous option`. Upgrade fixes.

### Phase 1 — 19 additional correctness/quality items (H/M/L)

- **H1/H2** `integrations_v28`: `f.extra[...]` mutations guarded with
  `isinstance(f.extra, dict)` at the write site in `osv_dev_enrich` +
  `exploitdb_xref`.
- **H3** `_post_json` refuses non-HTTPS webhook URLs by default; opt
  out via `WPSECSCAN_ALLOW_INSECURE_WEBHOOK=1` for localhost dev.
- **H4** `buildkite_annotation` sanitizes `report.target` before
  `subprocess.run` (defends against downstream re-shell).
- **H5** `auto_control_mapper` returns an explicit "not yet shipped"
  stub for SOC2 (was incorrectly mapping to NIST 800-53 IDs).
- **M1-M10 + L2-L10** — see commit log for the full list including:
  PyYAML safe-dump for Nuclei templates (M5), atomic write for
  GitLab CI (M6), `voice_query` removal (M3, always returned skipped),
  multisite REST-API detection (M9), tighter `global_styles_css_injection`
  trigger (L8), tighter `tenant_isolated_home` validation (L6),
  `attestation_letter` frozen-exe-safe version import (M2).

### Phase 2 — Wire dead v28 modules to real CLI surface

The v2.8.1 audit found `integrations_v28`, `ai_v28`, `compliance_v28`,
`cli_error`, `json_migrations` shipped in the wheel but were never
imported from any production path. v2.8.2 surfaces them via three new
umbrella subcommands:

- **`wpsecscan emit <FORMAT> <REPORT.json> [--out FILE]`** — 14 formats:
  spdx-sbom, intoto, cef, leef, cab, risk-csv, risk-json,
  attestation-letter, hipaa-map, fedramp, ce-plus, e8,
  stakeholder-bundle, gdpr-dpia.
- **`wpsecscan push <PROVIDER> <REPORT.json>`** — 13 providers:
  gitlab-ci, circleci, azure-devops, buildkite, shortcut, plane, wiz,
  chat, hosting, automation, osv-enrich, exploitdb-xref, nuclei.
- **`wpsecscan ai <SUB> ...`** — 6 helpers: remediation, plan,
  visual-diff, injection-check, drift, control-map.

All three use `cli_error.CliError` + `handle_cli_error` for structured
errors, exercising the previously-dead `cli_error` module.

### Phase 3 — +75 tests (930 → 1005)

- New `tests/test_v281_dead_code.py` (27 tests): C1+C2 regression
  guards, `cli_error` plain+JSON, `json_migrations` round-trip for 3
  upgraders + backup option, `integrations_v28` HTTPS enforcement +
  subprocess sanitisation + atomic write, `ai_v28` PI detector +
  budget fallback + SOC2 stub + path-traversal rejection,
  `compliance_v28` CEF/LEEF/CSV/HIPAA/SPDX/in-toto.
- New `tests/test_v281_new_checks.py` (48 tests): happy-path +
  empty-response for all 17 F2-F23 checks plus parametrised
  crash-on-empty regression guard.
- Extended `tests/test_new_check_inventory.py` `NEW_PASSIVE` to cover
  all 17 v2.8.1 check IDs.

### Phase 4 — 11 UX quick wins

**CLI**: `check list --json` (machine-readable inventory), `--format`
"did you mean?" suggestions, `--diff-since` parse failure → exit 2,
`WPSECSCAN_OUT_DIR` env var, `sites --help` annotated examples,
`--shell` REPL Tab completion via readline+rlcompleter, expanded
`--prove` help.

**GUI**: Context-menu "Copy finding (JSON)"; scan-start status bar
shows ETA via `eta.estimate_scan_seconds`.

**Reporter**: SARIF deterministic ruleId ordering (CI-diff-friendly);
new `--md-frontmatter` flag for Hugo/Obsidian/MkDocs YAML front-matter.

Deferred to v2.9.0: GUI U#5 (already present), U#10 (existing
context-menu equivalent), U#11 (empty-state Treeview painting), U#13
(cross-window history wiring).

### Phase 5 — docs + CI

- README badges: `checks-270` → `checks-293+`, `tests-780` → `tests-1005`.
- FEATURES.md: stale `monitors.py` reference removed.
- New `docs/whats-new.md`, `docs/sdk-helpers.md`, `docs/troubleshooting.md`.
- CI matrix extended to Python 3.13.

1005 tests pass.

### Deferred from v2.8.2 to v2.9.0
See `.claude/plans/v2.9.0.md` for the full queue.

- **GUI U27** — toolbar tab-order audit
- **GUI U30** — "new since your last version" highlighting in the
  in-app changelog viewer
- **GUI U32** — multi-target ttk.Treeview window
- **F39** — local RAG CVE corpus (XL — 2GB index)
- **F46** — offline quantized model bundle (XL — 2GB GGUF)
- **T2** — full `_v27` subpackage rename (touches dozens of imports;
  v2.8.1 instead ships *new* integrations_v28 / ai_v28 / compliance_v28
  modules so existing _v27 modules stay as-is)
- **T3** — migrate ~10 `while i < len(args)` loops + ~10 raw
  `home_dir() / "...json"` sites to `_util` helpers
- **T7** — full auth wiring (RBAC + SSO + approval-workflow)

## [v2.8.1] — 2026-05-31

The single-release execution of the entire v2.8.0 deferred backlog
(~83-101 items). Ships in 7 phases per `.claude/plans/calm-discovering-spindle.md`.

**Counts**: 17 new defensive WP checks · 11 CLI/GUI UX
improvements · 13 integrations · 11 AI helpers · 16 compliance
& enterprise features · 4 architectural changes · 11 bug fixes
deferred from v2.8.0. ~80 distinct fixes/features shipped.

### Phase 1 — Bugs (11) + CLI UX (5) + GUI UX (7)

- **B14-followup** Bundle full 2048-word BIP-39 wordlist at
  `wpsecscan/data/bip39-en.txt`; closes symmetric false-negative.
- **B24** `reporters/issue_export.py` — shlex.quote every
  interpolation in jira_curl_commands.
- **B28** Deleted `checks/http2_smuggling.py` — httpx client-side
  CRLF validation made the detection unreachable.
- **B31** `auditor_pdf` derives `lang=` from TLD (de/fr/jp/…).
- **B33** `mobile_api` token storage `localStorage` → `sessionStorage`.
- **B35** `daemon/_legacy` PID-file with O_EXCL + liveness probe.
- **B37** Help epilog table layout fix.
- **B39** `_atomic_write_text` helper used by 28 reporters.
- **B41** `_util.validate_out_path` centralises --out validation.
- **B44** `--json-ascii` flag for ASCII-only JSON output.
- **B45** Spider netloc IDN normalisation via `.encode("idna")`.
- **U1** Grouped --help epilog (Scanning, Reporting, Integrations,
  AI, Auth, Compliance, Marketplace, Vuln DB, Utility).
- **U6** `--resume <id|list>` for attack_checkpoint state.
- **U7** `--output` as alias for `--format`.
- **U9** CI-aware progress fallback: dot-per-check on dumb terminals.
- **U10** `wpsecscan doctor --json` + non-zero exit on any failure.
- **U11** `--self-update` for pip installs.
- **U13** `--fail-on` argparse type=validator.
- **U16** `--timeout` warning always emitted to stderr.
- **U17** Batch --file scans show ETA at start + remaining time per site.
- **U3** Interactive TTY prompt when target URL is missing.
- **U4** Fish shell completion via `--completion fish`.
- **U14** Confirmation prompts on bulk `creds rm` + `snooze clear`.
- **U15** `cli_error.CliError` dataclass for structured errors.
- **U20** "Skip Everything" button in first-run Defender dialog.
- **U22** Persistent window geometry (already shipped earlier).
- **U31** Error dialog with inline Retry + Copy buttons.
- **U33** Recent Targets combobox grouped (Profiles + Recent).

### Phase 2 — 17 new defensive WP security checks (F2-F23)

`wc_cart_abandonment_xss`, `wc_draft_order_escalation`,
`wc_payment_link_replay`, `stripe_connect_state_csrf`,
`plugin_update_server_integrity`, `wp_auto_update_filter_exposure`,
`activitypub_data_leak`, `synced_pattern_leak`,
`global_styles_css_injection`, `multisite_network_option_idor`,
`multisite_super_admin_rbac`, `rest_only_admin_probe`,
`nextjs_env_var_exposure`, `ai_agent_tool_injection`,
`wc_multivendor_idor`, `webauthn_rp_id_audit`, `wc_refund_flow_idor`.
All registered in `checks/__init__.py` with OWASP/ATT&CK/CWE/D3FEND
tags + PCI/NIST/ISO/HITRUST/CMMC/CIS-v8/ISO-2022 compliance mappings.

### Phase 3 — 13 integrations (`integrations_v28`)

GitLab CI Code Quality JSON · CircleCI Insights webhook · Azure
DevOps Boards work-item · Buildkite annotation · Shortcut story ·
Plane.so issue · Nuclei template export · OSV.dev enrichment ·
ExploitDB CSV xref · Wiz/Lacework webhook · Mattermost/RocketChat/
Telegram chat · WP Engine/Kinsta hosting event · n8n/Make.com/Notion/
Power Automate/Patchstack-in automation webhook.

### Phase 4 — 11 AI features (`ai_v28`)

Agentic remediation loop · self-improving scan plan · admin-panel
screenshot vision · visual-diff summariser · voice-query wrapper ·
sandboxed exec (bwrap/sandbox-exec) · prompt-injection detector ·
disk-cached LLM · cheaper-model fallback ladder · SOC2/HIPAA/PCI/ISO
auto-control mapper · risk-score anomaly drift alert.

### Phase 5 — 16 compliance + enterprise features (`compliance_v28`)

HIPAA §164.312 safeguards · GDPR Art.35 DPIA pre-screen · FedRAMP
Moderate baseline · UK Cyber Essentials Plus · Australia Essential 8 ·
SPDX 2.3 SBOM · in-toto Statement v0.1 · ArcSight CEF + IBM LEEF ·
Sigstore Rekor witness · SCIM 2.0 user→creds · per-tenant home ·
white-label PDF theme · Change Advisory Board export · risk-register
CSV/JSON · attestation letter · per-stakeholder bundle (CISO/CIO/
DevMgr) · CMMC 2.0 Level 2 evidence ZIP.

### Phase 6 — 4 architectural (T5/T6/T9/T10)

- **T5** `docs/marketplace.json` scaffold for GitHub Pages marketplace.
- **T6** `json_migrations` module with sniff-and-upgrade pattern
  for the 4 unversioned local-state JSON files.
- **T9** Deleted dead `monitors.py` (540 LOC, zero callers).
- **T10** New `wpsecscan ai-triage <SUB>` CLI subcommand surfaces 6
  previously-dead ai_triage helpers (tickets/timeline/impact/
  exec-brief/kev).

930 tests pass.

## [v2.8.0] — 2026-05-31

Third mega bug + code-quality discovery pass (12 parallel audit
agents) PLUS the deferred v2.8.0 tidy backlog + 5 picked features +
8 picked UX quick-wins. Largest release in project history.

Tests: 885 → ~915+ passing. **57 fixes/additions** total:
- **46 bugs** verified + fixed (4 Critical, 15 High, 14 Medium,
  10 Low + 2 false-positives ruled-out + a few too-big-for-this-
  release items deferred to v2.8.1)
- **5 features**: F1 (WC coupon-enum check), F12 (headless CORS
  lockdown check), F17 (Trusted Types CSP detection), F41 (5-tier
  smart-explain), F64 (interactive HTML dashboard with filter+search)
- **8 UX**: U2 (did-you-mean fuzzy match), U5 (auto-config
  discovery), U12 (`wpsec` short alias), U21 (Escape in first-run
  dialogs), U23 (theme toggle persistence), U24 (High Contrast
  accessibility theme), U25 (Alt+S / Alt+R accelerators), U26
  (Ctrl+Q clean quit), U28+U29 (screen-reader accessible names +
  focus-triggered tooltips)
- **T1+T4 tidy**: 3 parked test files committed, pyproject extras
  (`aws`/`tts`/`push`), upper bounds on `test` + build-system deps,
  dead-code purge (`verify_claim`, `worker_pool_scan`, `has_http3`,
  GPU stub)

T2/T3/T5-T10 (the rest of the original v2.8.0 tidy backlog)
deferred to **v2.8.1** because they need bigger refactors:
- T2 (`_v27` rename) blocked by namespace conflicts —
  `wpsecscan/integrations/`, `wpsecscan/perf/` directories already
  exist as subpackages; `wpsecscan/marketplace.py`,
  `wpsecscan/education.py` already exist as different modules.
  Clean "drop in place" needs the subpackage refactor.
- T3 (argparse + load_home_json migration) — per-site review of
  10 + 10 sites is non-trivial.
- T5-T10 — each needs its own design RFC (GH Pages publish, state
  schema migration, auth wiring, monitors/ai_triage decisions).

### Security — Critical

- **B2** `checks/websocket_audit.py` — `request.encode()` crashed
  `UnicodeEncodeError` on IDN target hostnames (e.g.
  `café.example.com`). Punycode-encode via `host.encode("idna")`
  before interpolating into the raw HTTP request.
- **B3** `checks/tls_reneg_dos.py` — same IDN crash path; same
  fix. Both .encode() and socket.create_connection use ascii_host.
- **B4** `daemon/_legacy.py` — daemon report files (.json/.html)
  used bare `write_text`; SIGTERM mid-write corrupted output.
  Now routed through `history._atomic_write_text` (v2.7.3 helper).
- **B5** `daemon/_legacy.py` + `api_server.py` — installed SIGTERM
  (+ SIGHUP where available) handlers. `docker stop` /
  systemd `Restart` / logrotate's SIGHUP no longer kill mid-scan.

### Security — High

- **B6** `__main__.py` — removed duplicate `--quiet`/`-q`
  registration (was at lines ~1039 and ~1133)
- **B7** `__main__.py` — `--password-audit` bad input exit 1 → 2
- **B9** `__main__.py` — `--tldr` exit code honours `--fail-on`
  threshold (0 or 1), not raw severity rank 0-4
- **B10** `reporters/sarif.py` — coerce None title/evidence to ""
- **B11** `reporters/console.py` — coerce None evidence in plain-
  text Rich fallback
- **B12** `reporters/json_out.py` — `_sanitise_json_floats()` walks
  the report replacing NaN/Inf with None; `allow_nan=False` belt-
  and-braces. Output is now always valid RFC 8259 JSON
- **B13** `checks/referenced_buckets.py` — R2 listing detection
  requires the same XML signature as S3 (was any 200 → false
  positive on every CDN-backed asset)
- **B14** `checks/wallet_seed_phrase_leak.py` — threshold 8/12 →
  12/12 against the partial BIP-39 wordlist; eliminates English-
  prose false positive (full 2048-word list bundling deferred to
  v2.8.1 to close the symmetric false negative)
- **B15** `checks/subdomains.py` — DANGLING_CNAME_FINGERPRINTS
  `_cname_frag` was extracted but never validated; now socket.
  getfqdn resolves the chain and BOTH CNAME provider fragment +
  body marker are required
- **B16** `checks/email_security_deep.py` — `_resolve_txt` honours
  `WPSECSCAN_NO_LIVE` env so nslookup/dig subprocesses don't
  bypass the no-network gate other checks respect
- **B17** `ai_safety.mask_private` — email regex Unicode-aware
  (`re.UNICODE` + `\w`); IDN domains + non-ASCII local parts
  now redacted before hitting LLMs
- **B18** `checks/tls_deep.py` + `checks/tls_headers.py` —
  locale-independent X.509 date parser (`_parse_cert_date_en`
  with hardcoded English month map); replaces
  `strptime("%b %d ...")` which silently failed on
  Turkish/German/Japanese hosts
- **B19** `mobile_v27.web_push_register` — allow-list of known
  push-service origins (FCM, Mozilla autopush, Apple WebPush,
  MS notify, HuggingFace push). Stops data-exfil via crafted
  subscription registration. `WPSECSCAN_WEB_PUSH_EXTRA_HOSTS`
  env extends for operators with their own relay
- **B20** `api_server.py` — `_SCAN_SLOTS` semaphore (default 8,
  `$WPSECSCAN_API_MAX_CONCURRENT` to raise). POST /scan returns
  HTTP 429 immediately when cap is reached. Stops unbounded-
  thread resource exhaustion
- **B21** `api_server.py` /healthz — real readiness signal:
  scan_slots_free, ready, not_ready_reasons. New /readyz endpoint
  returns 503 alone when not ready. K8s/LB no longer route
  traffic to saturated instances

### Bug fixes — Medium

- B22 `--no-console` alias now documented in --help
- B23 `verify-release` no-tools exit 2 → 69 (EX_UNAVAILABLE)
- B26 `csv_export_csp` skips plain negative numbers (CSV literals)
- B27 `gdpr_dsr_endpoint_enum` precise body equality vs substring "0"
- B29 nginx EOL table refreshed for 2026 (1.24 EOL, 1.28 current)
- B30 `http.py` HAR body decode honours response.encoding
- B32 `integrations_v27.push_gcp_scc` SHA-256(title) finding_id;
  stable across locales, no UTF-8 mid-codepoint slicing
- B34 `mobile_api` Windows path traversal — reject backslash etc.
  BEFORE Path round-trip
- B38 `compliance audit` clearer error when sub-sub-command missing
- B40 `markdown.py` reporter — 4-backtick fence (CommonMark) instead
  of 3-backtick + ZWS hack
- B42 `gutenberg_blocks` VERSION_RE word-boundary fix
- B43 `csrf_nonce` FORM_RE accepts unquoted `method=post`
- B46 `mobile_api` default bind 0.0.0.0 → 127.0.0.1
- B47 daemon cron uses UTC (was local time; DST broke it)
- B48 daemon cron dedup comment + cleanup logic clarified

### Skipped / ruled out
- B1 (heatmap_svg |safe XSS): verified false positive
- B8 (`--format json,html`): intentional behaviour
- B25 (bounty_format severity None): already correctly handled
- B24/B28/B31/B33/B35/B37/B39/B41/B44/B45: deferred to v2.8.1

### Features (5 picked from a 65-feature menu)

- **F1** new check `wc_coupon_enum.py` — WC coupon enumeration
  oracle detection
- **F12** new check `headless_cors_lockdown.py` — WP REST CORS
  policy audit for headless deployments
- **F17** `csp.py` extended with Trusted Types directive detection
  (`require-trusted-types-for 'script'` + `trusted-types` policy
  whitelist)
- **F41** `ai_assist.py` extended client_summarize_finding to 5
  audience tiers (added `pm`, `sec_eng`, `wp_expert`)
- **F64** `data/report.html.j2` interactive filter bar + search
  input. Single-file (no Chart.js dep). Toggle severity buttons,
  full-text search across visible findings, live counter.

### UX (8 picked from a 31-item menu)

- **U2** `__main__.py` "did you mean?" fuzzy suggestion via
  `difflib.get_close_matches`
- **U5** `__main__.py` auto-discover `.wpsecscan.toml` in cwd
- **U12** `pyproject.toml` `wpsec` short alias entry point
- **U21** `gui.py` Escape binding in every first-run dialog
- **U23** `gui.py` theme toggle (View menu) persists via
  `_save_pref("theme", ...)`
- **U24** `gui.py` High Contrast accessibility theme (WCAG-AA;
  black bg / yellow fg / white borders)
- **U25** `gui.py` Alt+S start scan, Alt+R open report accelerators
- **U26** `gui.py` Ctrl+Q clean quit (routes through unified
  _on_window_close handler)
- **U28+U29** `gui.py` `_Tooltip` now fires on `<FocusIn>` and
  sets `text=`/`takefocus=1` so screen readers announce icon-only
  toolbar buttons by name

### Tidy / tech debt

- **T1** Committed 3 parked test files (test_edu_v27, test_perf_v27,
  test_trust_v27) that had been sitting untracked since v2.7.1
- **T4** `pyproject.toml` extras: `aws` (boto3), `tts` (gTTS +
  pyttsx3), `push` (pywebpush); upper bound on `test` (pytest<9);
  build-system bounded (setuptools<82, wheel<1)
- **T4** Dead-code purge: `ai_safety.verify_claim` (#68; self-
  referential), `perf/_legacy.worker_pool_scan` (#86), `has_http3`
  (#83), `#84` GPU stub. All zero callers per audit grep.
- T2 (`_v27` rename), T3 (helpers migration), T5 (GH Pages
  publish), T6 (versioned-JSON state migration), T7 (auth
  wiring RFC), T9/T10 (dead-module decisions) → v2.8.1.

### Discovery cost note

12-agent parallel audit (6 bug-audit on rotated lenses + 4
feature-ideation + 2 UX-ideation) surfaced ~170 raw items. After
verification (false-positive discipline) and culling, presented
107 numbered items to the user. User picked everything; the
auto-split policy ships ~69 items in v2.8.0 and defers ~83 to
v2.8.1 (see `.claude/plans/v2.8.1.md`).

## [v2.7.3] — 2026-05-29

Second mega bug + code-quality audit hot-fix. 9 parallel agents
(security, correctness, concurrency/IO, crypto, PHP companion,
dependencies, AI helpers + prompt injection, GUI + IPC,
maintainability + test coverage) surfaced 23 actionable findings.
Critical + High + High-infra ship in this release; Medium/Low
findings + the deferred auth-package wiring (rbac/sso/approval)
roll into v2.8.0.

Tests: 818 → 862 passing + 2 platform-skipped. Companion plugin:
1.4.2 → 1.4.3. **44 new regression tests** across 5 new test files,
each authored test-first and confirmed red on pre-fix code.

### Security — Critical

- **N1** `interactsh.py` — `InteractshSession` was completely broken.
  Four attribute assignments (`url_http`, `url_https`, `interactions`,
  `started_at`) sat below a `return server` inside the
  `@staticmethod _validate_server`, so they never ran AND referenced
  `self` from a static context (NameError if reached). Any caller
  hit AttributeError. Out-of-band scanning was non-functional.
  Moved the four assignments into `__init__` where they belong.
- **N2** `ai_assist.py` — every LLM call site interpolated user
  `question` + scan-controlled `finding.title`/`evidence`/
  `remediation`/`url` into prompts **without** piping through
  `safe_for_llm()` / `strip_prompt_injection()`. Prompt injection
  was wide open. Every interpolation now runs through `_safe()`
  (`ai_safety.safe_for_llm` alias). Covers `remediation_augment`,
  `query`, `answer_compliance_question`, `fix_pr_body`,
  `evidence_summary`, `threat_model_js`, `fix_pr_diff`,
  `client_summarize_finding`.

### Security — High

- **N3** `gui.py` — single `WM_DELETE_WINDOW` handler. Pre-fix
  registered twice in `__init__`; activity-bus cleanup at line 771
  was overwritten at line 788, AND scan thread was never joined on
  close. In tray mode `root.destroy()` was never reached so the
  40ms `after()` poll loop fired against a withdrawn window
  indefinitely. New `_on_window_close` method cancels the scan
  thread, unsubscribes the activity bus, then routes to
  `tray.hide_to_tray` (which falls through to `destroy` when no
  tray icon).
- **N4** `reporters/share_link.py` — `_share_secret` switched
  `O_TRUNC` → `O_EXCL`. The pre-fix flag silently regenerated the
  share secret if the `exists()`/`open` race window was hit,
  invalidating every previously-issued share link. On
  `FileExistsError` we now read the racing process's secret.
- **N5** `interactsh.py` — `_random_id` switched
  `random.choices` → `secrets.choice`. `random.*` is reseeded by
  `trust_v27.set_deterministic_seed()`, so the OOB correlation ID
  was predictable to another scanner on shared `oast.live`.
- **N6** `history.py` — added `_atomic_write_text()` helper and
  migrated 4 state-file writers (`push_url`, `save_profile`,
  `_save_annotations`, `_save_comments`). Concurrent scan sessions
  no longer corrupt history / profiles / annotations / comments
  files mid-write.
- **N7** `history._snapshot_signing_secret` — was world-readable
  (no 0o600 mode) AND raced (`exists()`/`write_text` TOCTOU); loser
  silently overwrote winner's secret, invalidating every snapshot
  signed before the race resolved. Now `O_EXCL` atomic create with
  `0o600`; on `FileExistsError` read the racing process's secret.
- **N8** `observability.tail_activity_log` — was `if not p.exists():
  p.touch()`, which on Windows truncates an existing file silently
  and on POSIX has a TOCTOU window. Switched to atomic `O_EXCL`
  create that ignores `FileExistsError`.
- **N9** `trust_v27.reproducible_build_verify` —
  `os.environ.setdefault("SOURCE_DATE_EPOCH", ...)` mutated the
  live process environment, leaking the timestamp into every
  subsequent subprocess in the same Python process. Now passed
  per-subprocess via `env=`; caller environment stays clean.
- **N10** `ai_safety.strip_prompt_injection` — expanded to cover
  Llama/Mistral `[INST]`/`[/INST]` markers, Anthropic
  `<human>`/`<assistant>`/`<system>` tags, role-prefix boundaries
  at start-of-line (`Assistant:`/`Human:`/`System:`/`User:`), AND
  zero-width unicode (ZWSP, ZWNJ, ZWJ, soft-hyphen, BOM, word
  joiner) that could smuggle invisible payloads past byte-level
  pattern matching.
- **N11** `ai_safety.mask_private` — expanded to cover OpenAI keys
  (`sk-*`, including `sk-proj-`, `sk-svcacct-`, `sk-org-`), GitHub
  OAuth/server/user-server tokens (`gho_*`, `ghs_*`, `ghu_*`),
  database DSNs (postgres/mysql/mongodb/redis/amqp(s)), Slack
  bot/user/legacy/refresh tokens (`xoxb-`, `xoxp-`, `xoxa-`,
  `xoxr-`, `xoxs-`), Slack incoming webhook URLs, Hugging Face
  tokens (`hf_*`), Anthropic API keys (`sk-ant-*`).
- **N12** `ai_triage.py` — LLM-returned JSON deserialised + indexed
  directly without schema validation. A jailbroken or misbehaving
  LLM could return `{"fp_prob": 1.0}` for every finding, auto-
  suppressing the entire report. Added `_validated_dicts()` (top-
  level list-of-dicts shape check + required-key gate) and
  `_clamp_unit()` (numeric range gate). Applied at
  `score_findings_by_context` and `predict_false_positives`.
- **N13** companion `/php-error-log-tail` — was returning the raw
  `ini_get('error_log')` value (absolute server filesystem path).
  Now returns `log_configured` boolean + basename only.
- **N14** companion `/file-monitor` — `roots` was exposing
  `WP_PLUGIN_DIR` + `get_theme_root()` absolute paths. Now returns
  relative paths (`wp-content/plugins`, `wp-content/themes`).
- **N15** `gui.py` — admin password was persisted **plaintext** in
  `~/.wpsecscan/profiles/<name>.json`. Now routed through
  `creds_vault.set_secret()`; profile stores only a vault
  reference. Legacy plaintext profiles still load for one cycle
  (migrated on next save).
- **N19** companion `/plugin-license-keys` — dropped the
  `length_bucket` (short/medium/long) field. 2-char prefix + a
  length bucket meaningfully reduced the brute-force search space
  for short keys; the bucket added no scanner value. Mask format
  is now `<2-char-prefix>...`.

### Infrastructure / supply chain

- **N16** SHA-pinned every action across the remaining 4
  workflows (`tests.yml`, `ossf-scorecard.yml`, `cve-feed.yml`,
  `wpsecscan.yml`); v2.7.2 C27 only covered the release-critical
  pair. Verified `grep` returns zero unpinned actions. Dependabot
  keeps these current.
- **N17** Version-pinned every `pip install` in CI
  (`pytest==8.3.4`, `pyyaml==6.0.2`, `pip==25.3`,
  `pyflakes==3.2.0`, `pyinstaller==6.13.0`, `httpx==0.28.1`).
  `build-exes` (which produces the user-facing `.exe` files) was
  the highest-risk previously-unpinned site.
- **N18** `wpsecscan.yml` (demo workflow) —
  (a) Replaced `git clone --depth 1` of unpinned `main` with
  `pip install 'wpsecscan==2.7.3'`. Pushes to main no longer
  silently change what the demo installs.
  (b) Replaced inline `${{ secrets.WPSCAN_TOKEN && format(...) }}`
  shell expansion with `env:` block + bash array — eliminates
  shell-injection if the token ever contains `$`, `;`, or
  backtick.

### Code-quality / wiring

- **N20-partial** `audit_log.append()` wired into the highest-
  value production paths (`creds_vault.set_secret` /
  `delete_secret`, `marketplace_v27` install success/failure +
  verify). Pre-v2.7.3 the entire `auth/` package was dead code
  in production. Added `safe_append()` convenience wrapper that
  derives the actor automatically (`WPSECSCAN_ACTOR` env >
  `$USER`/`$USERNAME` > `getpass.getuser()` > `cli`) and
  swallows audit-log write failures so a disk-full or
  permission error can never break the operation being audited.
  Cleartext secret values are NEVER logged (only the field
  length).

### Deferred to v2.8.0

- Wiring the remaining auth modules (rbac, sso_oidc, sso_saml,
  approval_workflow) into production — needs an RFC for CLI
  gating UX and headless-mode actor identity.
- Wiring `monitors.py` (540 LOC, all 15 public functions dead)
  and the 6 dead `ai_triage` functions — feature decisions.
- ~15 Medium findings (UAC popen zombie, cosign no timeout,
  etag_get TOCTOU, audit_log handler OSError leak, generate_tickets
  no global LLM budget, Ollama no max_tokens, `report.target` in
  system prompt position, companion token transient cleartext,
  database-encoding query no `prepare()`, `pytest>=7.4` no upper
  bound, `setuptools` build-system unbounded, `gui.py` LOC
  outlier, `perf/_legacy` worker_pool_scan dead,
  `workflow_cmds.py` zero test coverage).
- ~15 Low findings (Slack scan-snippet leak, `ssl.CERT_NONE`
  probe docs, PID-suffix collision, `gcp_scc` count, diff quirk,
  log_action atomic, env-var names in errors, uninstall option
  cleanup, innerHTML pattern, update-check sig, verify_claim
  dead, no LLM I/O logging, asyncio fragility, `_legacy` GPU
  stub, YAML claim).

### Ruled-out false positives

Re-verified: `$wpdb->prefix` SQL interpolation (WP core
guarantees alphanumeric+underscore), `args[i+N]` enumerate
arithmetic (lands at right slot), `hmac.new` positional digestmod
(documented API), `wp_check_password` (WP-native bcrypt path).

## [v2.7.2] — 2026-05-28

Mega bug-check audit hot-fix. A 6-agent parallel sweep (security,
correctness, concurrency/IO, crypto/secrets, PHP companion,
dependencies/supply-chain) flagged 27 actionable findings on top of
v2.7.1. This release ships fixes for all of them across 5 commits.
Tests: 790 → 818 passing + 2 platform-skipped. Companion plugin:
1.4.1 → 1.4.2.

### Security — Critical

- **C1** `marketplace_v27.py` (install + verify) — sigstore sig/pem
  URLs were fetched from any host (v2.7.1 S1 only protected
  `source_url`), AND cosign was invoked with wildcard identity +
  issuer regexps. Combined: a malicious or MITM'd index could ship
  its own cert+sig pair and pass verification ⇒ RCE on install.
  Now: sig/pem must come from the marketplace origin too; cosign
  identity anchored to the index's `author_handle`, OIDC issuer
  pinned to GitHub Actions. Refuses verify if author_handle is
  missing/malformed.
- **C2** `auth/audit_log.py` — `expected != stored_hmac` short-
  circuited on the first differing byte. An attacker who could
  append entries and re-trigger `verify_chain` could byte-by-byte
  forge a valid HMAC for a tampered prior entry. Switched to
  `hmac.compare_digest`.

### Security — High

- **C3** `auth/audit_log.py` — HMAC key file now created with
  `O_EXCL|0o600` atomically (no create-then-chmod race window).
- **C4** `reporters/share_link.py` — share-link payload now signs
  `issued_at` + `expires_at` (30d default TTL); `verify()` rejects
  expired or pre-v2.7.2 (no-TTL) payloads. Adjacent: `_share_secret`
  no longer `.strip()`s on read (~0.8% of random 32-byte secrets
  had a trailing-whitespace byte, breaking signature verification
  intermittently).
- **C5** `gui.py` — toast notifier switched from f-string-into-Popen
  to PowerShell `-EncodedCommand` (base64 UTF-16LE). Finding titles
  with `'` or `"` no longer break the command boundary.
- **C6** `gui_v27_extras.py` — Start-Menu shortcut creator: same
  EncodedCommand fix for paths containing apostrophes.
- **C7** `__main__.py` (×3) — three off-by-one bounds guards
  (`i + N < len(args) + M` → `i + N < len(args)`) at `check-new
  --name`, `gh-check-run --fail-on`, `diff-agency --out`. Crashed
  with IndexError on trailing-flag typos.
- **C8** companion `includes/rest.php` (`/users-with-app-passwords`)
  — returns `email_sha256` instead of plaintext `user_email`, matching
  the `diagnostics.php` pattern. Companion plugin 1.4.1 → 1.4.2.
- **C9** `checks/login_redirect_http_hop.py` — unconditional
  `verify=False` replaced with the project-wide `WPSECSCAN_INSECURE_
  TLS` env-var opt-in. MITM could otherwise suppress the http-hop
  finding by forging the redirect-chain probe.
- **C10** `trust_v27.py` — sdist `tarfile.extractall` now uses
  `filter="data"` on Python 3.12+ with member pre-validation on
  older Pythons. Malicious sdist with `..` members can't escape
  the workdir.
- **C11** `api_server.py` — startup banner no longer echoes
  `token[:6]` (37.5% of a 16-char API token).

### Bug fixes — Medium

- **C12** `perf_v27.etag_set` — atomic temp + `os.replace`; two
  parallel workers can no longer truncate the shared ETag cache.
- **C13** `continuous_monitor` — same atomic pattern for the
  polling-loop state file.
- **C14** `hardware_keys.tpm_seal` / `tpm_unseal` — `primary.ctx`
  is now an absolute path (was bare relative filename, resolved
  against caller's cwd).
- **C15** `history.save_report_snapshot` — write the timestamped
  snapshot first, then atomic `os.replace` the "latest" pointer.
  Crash mid-save can no longer leave latest pointing at a missing
  snapshot.
- **C16** `integrations_v27.import_snyk_findings` — rebinds
  non-dict `f.extra` to `{}` so the dedup write no longer raises
  `TypeError` on JSON-null-deserialised findings.
- **C17** `creds_vault._save_index` — index file (lists every
  stored credential identifier) now `os.open(O_CREAT|0o600)`,
  no longer inherits process umask.

### Code quality / low — Low

- **C18** `checks/authenticated.py` — auth-debug body slice now
  piped through `mask_private` (was raw response.text[:500]).
- **C19** `ua_rotation.py` — `random.choice` → `secrets.choice`
  so the UA rotation sequence isn't predictable after
  `set_deterministic_seed` reseeds the random module.
- **C20** `perf/_legacy.py` memo cache — SHA-1 → SHA-256 cache key.
- **C21** `integrations_v27.push_gcp_scc` — log GCP-side push
  failures to stderr instead of swallowing silently.

### Infrastructure / supply chain

- **C22** `pypi-publish.yml` — migrated to PyPI Trusted Publishing
  (OIDC). No long-lived `PYPI_API_TOKEN` secret required.
- **C23** `release-attestation.yml` — SLSA build-provenance +
  Sigstore signatures + SHA256SUMS now cover sdist (.tar.gz) and
  wheel (.whl) too, not just the .exe / .zip binaries.
- **C24** `release-attestation.yml` — verification snippet now
  uses a workflow-path-anchored identity regexp, not just the
  repo URL prefix.
- **C25** `release-attestation.yml` — pinned `cyclonedx-bom==4.4.3`
  (was unpinned in a job with `id-token: write`).
- **C26** `pyproject.toml` — added upper bounds to every `>=N`
  optional dep (Pillow<12, redis<7, reportlab<5, etc.).
- **C27** `.github/workflows/*.yml` — SHA-pinned every action in
  the release-critical workflows; existing Dependabot
  github-actions config keeps them current.

### Ruled-out false positives

The 6-agent sweep also flagged ~10 false positives that were
verified and ruled out, including alleged SQL injection via
`$wpdb->prefix` (WordPress core enforces alphanumeric), a 1-second
slack on the companion token TTL, and various `args[i+2]`
patterns where the index arithmetic actually lands at the right
slot. Documented in the audit notes; no fix needed.

## [v2.7.1] — 2026-05-27

Security hot-fix on top of v2.7.0. Three audits run in parallel against
the v2.7.0 surface surfaced three security-critical bugs plus five
medium-severity bugs concentrated in the new v2.7.0 modules. This
release fixes all eight; tidy + arch + missing-coverage items are
deferred to v2.8.0.

Companion plugin: **1.4.0 → 1.4.1** (3 fixes).

Tests: **778 → 790 passing + 2 platform-skipped** (+12 regression
tests pinning the fixes below).

### Security

- **S1** `marketplace install` (`marketplace_v27.py`) accepted ANY
  scheme + host for the package source URL — `file:///etc/shadow` would
  read local files; `http://evil.com/backdoor.py` would write arbitrary
  Python into `~/.wpsecscan/marketplace/checks/` and load it next scan.
  Now: source URL must be `https://`, host must match the marketplace
  index origin, slug must match `^[a-zA-Z0-9_-]{1,64}$`, and the
  Sigstore signature is verified inline (use `--allow-unsigned` to
  opt out for local development).
- **S2** `push_linear_triage` / `push_monday` (`integrations_v27.py`)
  built GraphQL mutations with f-string substitution. Finding titles
  flow from scan data which can contain operator-controlled text — a
  crafted title could break out of the string literal. Both backends
  now pass user-controlled values via GraphQL `variables`; query
  strings are static.
- **S3** `wp wpsec token` (companion `includes/cli.php`) wrote
  `'created_at'` but `rest.php` reads `'created'`. Every CLI-generated
  token compared as instantly expired. Companion plugin bumped to
  1.4.1.

### Bug fixes

- **B1** `cmd_worker` (`perf_v27.py`) — Redis queue entries are now
  required to start with `http://` or `https://` before being passed
  to subprocess.run; a target like `--config /etc/passwd` would
  otherwise have been interpreted as a CLI flag.
- **B2** `cmd_freeze` (`workflow_cmds.py`) — tarball arcnames now use
  `Path(...).name` so a maliciously-named snapshot can't escape its
  prefix on extraction (defence-in-depth; snapshot files normally
  contain no path separators).
- **B3** companion test-connection AJAX (`includes/admin.php`) — now
  CSRF-protected with `check_ajax_referer`.
- **B4** companion `/plugin-license-keys` (`includes/rest.php`) — mask
  reduced from 4-char prefix + exact length to 2-char prefix +
  bucketed length (short/medium/long); the endpoint still reports
  "license-key option exists" without leaking key shape.
- **B5** companion `/page-cache-info` (`includes/rest.php`) — per-file
  realpath boundary check skips symlinks that escape `WP_CONTENT_DIR`
  (cache_size_bytes / cache_file_count would otherwise include files
  outside the WP install).
- **B6** `statuspage_incident` (`integrations_v27.py`) — wraps
  `int(os.environ.get("STATUSPAGE_THRESHOLD"))` in try/except;
  malformed values now fall back to 50 with a stderr warning instead
  of an unhandled ValueError.
- **B7** `web_push_register` (`mobile_v27.py`) — `web-push-subs.json`
  now written via `os.open(..., O_WRONLY|O_CREAT|O_TRUNC, 0o600)` so
  subscription endpoints aren't world-readable.
- **B8** `cmd_replay_prompt` (`cli_extras.py`) — `replay-prompt-log.json`
  now written atomically via temp-file + `os.replace` so concurrent
  replay sessions can't corrupt the log.

## [v2.7.0] — 2026-05-27

Tests: **778 passing + 2 platform-skipped**. Check count: **268 → 270**.
Companion plugin: **1.3.0 → 1.4.0** (+6 endpoints). 22 commits, 11
phases. Fifth forward-audit delivery — the remaining **96 items** from
the post-v2.5.0 150-item brainstorm.

See git log v2.6.0..v2.7.0 for the per-commit breakdown. Major themes:

- Companion plugin v1.4.0 — 6 new REST endpoints (B38/B40/B41/B43/
  B44/B45) + WP-CLI `wp wpsec` command + update-check AJAX.
- 12 new reporters: share-link, Confluence/Notion live sync, PDF/UA
  metadata, xlsx-pivot, risk-forecast, heatmap SVG, OpenVEX, speakable
  JSON-LD, executive-TLDR, auto-PR patches, D3FEND mapping, GDPR DSR.
- 20+ new CLI subcommands: compare-portfolios, changelog, replay HAR,
  freeze, attest, compliance audit, tournament, ai-agent, triage,
  rotation, install-completion, replay-prompt, undo, worker, learn,
  audio-summary, marketplace, submit-cve.
- 15 new integrations: Vault, 1Password/Bitwarden, Snyk, HackerOne,
  VirusTotal/urlscan, Greynoise/AbuseIPDB, Sentinel KQL, AWS Security
  Hub, GCP SCC, Slack Connect, Teams reaction-snooze, Linear Triage,
  Asana/ClickUp/Monday, Statuspage, PagerDuty AIOps.
- 4 new AI helpers: evidence summariser, JS threat-modeller, compliance
  Q&A, changelog narrator.
- 9 GUI extras: gauge, filter chips, bookmarks, colour tags, onboarding
  tour, in-app changelog viewer, inline diff, pin-to-taskbar, fix-it
  clipboard.
- Real marketplace via GH-Pages-hosted index with cosign signature
  verification.
- Reproducible-build verifier + provenance graph + `--deterministic`.
- 2 new checks: Trellis YAML audit + headless WP on Vercel/Netlify
  detection; 1 perf-of-target check covering Core Web Vitals,
  Lighthouse, DB query budget, CDN cache hit ratio, cold-start probe.
- Web Push + iOS Shortcut + Watch complication + Android widget for
  the existing mobile-api PWA.

No public-API breaking changes. Every new feature is opt-in via
CLI flag, env var, or explicit subcommand.

## [v2.6.0] — 2026-05-27

Tests: **778 passing + 2 platform-skipped**. Check count: **226 → 268**
(+42 new). Companion plugin: **1.2.1 → 1.3.0** (+5 endpoints).

Fourth forward-audit delivery — 54 of the brainstormed 150 items
selected, weighted toward "most up-to-date" threat coverage (A1–A35 +
O141–O145) per user direction.

### Phase 1 — modern threats A1–A11 (3 commits)

**A1** AI plugin prompt-injection surface audit · **A2** AI chatbot
relay-endpoint + key leak · **A3** MCP (Model Context Protocol)
endpoint exposure · **A4** WP Playground / SQLite database-file
exposure · **A5** Gutenberg Block-Bindings custom-source audit · **A6**
Interactivity-API hydration PII leak · **A7** WP-CLI-over-HTTP endpoint
exposure · **A8** Application Passwords stale-token audit (auth) ·
**A9** WooCommerce Store API namespace drift · **A10** WC Subscriptions
duplicate-renewal race patch audit · **A11** Stripe / WooPayments
webhook signature audit.

### Phase 2 — modern threats A12–A28 (3 commits)

**A12** Klaviyo / Mailchimp list-ID enumeration · **A13** WP Multisite
SSO HMAC-key reuse audit · **A14** Algolia/Elasticsearch frontend
write-key leak · **A15** S3/R2/GCS shadow-bucket takeover · **A16**
Vercel/Netlify preview-URL leak · **A17** JWT-Auth plugin secret-key
audit · **A18** PWA service-worker precaches admin URLs · **A19** AMP
plugin transitional-mode open-redirect · **A20** Tracking cookies
firing pre-consent (ePrivacy/GDPR) · **A21** GDPR DSR ajax-action auth
check · **A22** REST plugin-install endpoint auth audit · **A23**
Form-builder file-upload bypass advisory · **A24** theme.json
font-source SSRF audit · **A25** Search-result `<mark>` reflected XSS
(active probe) · **A26** Site Health debug-dump SMTP credential leak ·
**A27** Polylang/WPML/TranslatePress API-key leak · **A28** WooCommerce
REST key scope advisory.

### Phase 3 — modern threats + WP 6.5/6.7/6.8 (3 commits)

**A29** Service-worker origin-wide scope hijack · **A30** HSTS preload
list vs header mismatch · **A31** CT-log shadow-certificate detection ·
**A32** Captcha sitekey placeholder/domain audit · **A33**
Discord/Slack/Telegram invite leak · **A34** Composer/npm typosquat
dependency advisory · **A35** CI-workflow (.github/workflows/) YAML
exposure on webroot · **O141** WP 6.8 Speculation-Rules audit · **O142**
WP 6.7 HTML-API breaks CSP nonces · **O143** WP 6.5 Font Library SSRF
audit · **O144** REST schema-callback field leak · **O145**
Block-Style-Variations URL-prop SSRF.

### Phase 4 — companion plugin v1.3.0 (1 commit)

**B36** `/users-with-app-passwords` · **B37** `/recent-uploads` · **B39**
`/wp-cron-event-history` · **B42** `/admin-notice-content` · **B47**
`/site-health-tests` (exposes WP core Site Health over token-gated REST).
Single scanner consumer `companion_v13.py` covers all five; no-op
without `--companion-token`.

### Phase 5 — AI + host-specific + polish (3 commits)

**G88** Local-model support via WPSECSCAN_OLLAMA_URL — verified ALREADY
SHIPPED in `ai_assist._call_ollama` since v2.3.0; noted in audit trail
for honesty. **G89** New `ai_assist.fix_pr_diff(finding)` + CLI flag
`--ai-fix-pr-diff CHECK_ID` writes `<stem>-CID-fix.patch` +
`<stem>-CID-fix.md`. **G90** New `wpsecscan/ai_fp_predictor.py` — pure-
Python Bayes classifier over snooze history; CLI flag
`--ai-fp-predictor` decorates `extra.fp_score` per finding.

**N136 + N139 + N140** Host platform detect — single
`host_platform_detect.py` covers Bedrock/Sage/Trellis (Roots),
WP Engine, Kinsta, Pantheon, Cloudways, WordPress VIP via response
headers + paths; emits per-platform advisories about platform-managed
controls (e.g. WPE ignores .htaccess; VIP enforces 2FA so
suppress duplicate checks).

**#67** New `wpsecscan kev URL` subcommand — CISA KEV-only fast-scan.
New `wpsecscan/kev.py` fetches the official catalogue (6h TTL cache)
and `filter_findings_to_kev()` keeps only findings whose
`extra.cve`/`extra.cves` appear in KEV. Exit 0 = clean, 1 = act now.

**#81** New `--tldr` flag — one-line summary to stdout
(`URL score=N/100 worst=SEV crit=… high=… …`); exit code = severity
rank 0–4. Suppresses all other output. Use:
`watch -n 60 wpsecscan https://x.com --tldr`.

### Notes

- `pyproject.toml` / `__init__.py` / `installer/wpsecscan-setup.nsi`
  bumped to 2.6.0.
- `wp-plugin/wpsecscan-companion` bumped 1.2.1 → 1.3.0 with 5 new
  endpoints inheriting all v1.2 hardening (token-pin, per-endpoint
  toggles, access webhook, HTTPS-only + private-IP-blocked).
- No public-API breaking changes. Every new check defaults to passive
  and is opt-out via `policy.yml` if not relevant.

## [v2.5.0] — 2026-05-27

Tests: **667 passing**. Third forward-audit delivery — all 80 items
from the post-2.4.0 brainstorm shipped (or honestly scope-downed) in
19 commits across 11 phases.

**Headline:** auth/login robustness rebuilt for hardened sites
(WP nonce, browser UA, CAPTCHA detection, login-URL discovery, 2FA
field expansion, XML-RPC AP fallback), 12 new companion-plugin REST
endpoints (active sessions, recent admin actions, db size, log files,
PHP error log tail, cron failures, anomalies, shell commands, object
cache, transient cache, wp-mail, multisite), live SIEM forwarders
(Splunk HEC / Datadog Logs / Loki / Beats), GitHub Check Run as a
PR-blocking status, Slack slash-command app, email-digest scheduler,
Teams Adaptive Cards, DD/NR dashboard templates, Redmine/Bugzilla/Trac
push, `creds` CRUD with OS-keychain + multi-account, SAML/OIDC
configure flow, hwkey gating for --aggressive, cron-syntax scheduler,
finding-level SLA tracker, AI auto-snooze + anomaly flagging,
Burp/ZAP import, plugin-zip pre-install scanner, Chrome MV3 + Firefox
browser extension overlay, reference-install diff against clean WP
archives, mobile companion PWA + REST.

### Added — Phase A: auth & login robustness (items 1–10)

- **#1**  `_wpnonce` extraction from `GET /wp-login.php` before POST.
- **#2**  Browser-like User-Agent on auth requests; `WPSECSCAN_AUTH_USER_AGENT` env override.
- **#3**  CAPTCHA / Turnstile / hCaptcha detection — abort with clear error.
- **#4**  Distinguish login-failure modes (wrong password / locked out / CAPTCHA / IP-banned).
- **#5**  Renamed-login-URL discovery + `WPSECSCAN_LOGIN_PATH` override.
- **#6**  2FA field expansion (3 → 12 plugin variants).
- **#7**  XML-RPC `wp.getProfile` fallback when REST returns 401/403/404.
- **#8**  Multi-step cookie capture across the redirect chain.
- **#9**  `--auth-debug` mode logs every step (sanitised) to ~/.wpsecscan/auth-debug/{host}.log.
- **#10** Successful auth strategy cached at ~/.wpsecscan/auth_strategy/{host}.json.

### Added — Phase B: companion plugin v1.2 endpoints (items 11–22)

12 new endpoints: `/active-sessions`, `/recent-admin-actions`,
`/wp-cron-failures`, `/scheduled-task-anomalies`, `/object-cache-info`,
`/transient-cache-size`, `/db-size-by-table`, `/log-files`,
`/php-error-log-tail`, `/cron-shell-commands`, `/wp-mail-deliverability`,
`/multisite-network-info`. Scanner-side consumers in `checks/companion_advanced.py`.

### Added — Phase C: companion admin UI + perf (items 23–32)

Test-connection AJAX, per-endpoint enable/disable toggles, IP-pin token
issuance, CSV export of activity log, configurable max-uses (1–100),
`/file-monitor` allowlist + incremental + subset + background wp-cron
pre-compute, outbound access webhook.

### Added — Phase D: CLI ergonomics (items 33–40)

- `--config FILE` / `--profile NAME` (YAML/TOML/JSON; precedence default<profile<config<CLI).
- `--format json,html,csv,md,xlsx,sarif,burp` consolidation.
- Short aliases `-A` `-P` `-F`.
- Shell-completion suggests values for `--fail-on`, `--ai-explain-for`, `--format`.
- `wpsecscan only CHECK_ID URL` — ad-hoc single-check probe.
- `wpsecscan doctor` — env audit.

### Added — Phase E: GUI feature gaps (items 41–49)

- OS keychain via `keyring` (Tools → Saved sites credential vault).
- Double-click finding → open URL in browser.
- Scan-completion system notification (plyer / winsound / Tk bell chain).
- Per-check heatmap pane (Tools menu).
- Filter box extended for CVE matching (`cve:CVE-N`).
- Scope-downs documented for #46 drag-drop, #48 reference compare (later landed in CLI as #79), #49 HAR viewer.

### Added — Phase F: reports (items 50–55)

- **#50** Full-evidence auditor PDF (reportlab + HTML fallback).
- **#51** SOC2 / ISO compliance-attestation matrix across 8 frameworks.
- **#52** Board-room 1-pager (3 numbers, 3 sentences, 3 actions).
- **#53** OpenAPI 3.1 schema for JSON output (`--print-openapi` to pipe).
- **#54** `--report-template TEMPLATE.html.j2` — user-supplied Jinja2.
- **#55** `wpsecscan diff-agency OLD.html NEW.html` — portfolio diff with exit-1-on-regression.

### Added — Phase G: power user (items 56–60)

- **#56** `wpsecscan check new SLUG` scaffold + 3 search dirs + `marketplace.json` publish.
- **#57** Boolean rule engine `severity_rules:` in policy.yml.
- **#58** Risk-weight override already shipped (`risk_weights.py`, noted in audit).
- **#59** `wpsecscan playbook {add|show|rm|list}` — user playbooks merged on top of bundled.
- **#60** `risk_formula:` in policy.yml — AST-allowlisted Python expression.

### Added — Phase H: integrations (items 61–67)

- **#61** SIEM forwarders: Splunk HEC, Datadog Logs HTTP intake, Grafana Loki push, Logstash HTTP input.
- **#62** `wpsecscan pr-status` — GitHub Check Run as branch-protection gate.
- **#63** `wpsecscan slack-app` — stdlib HMAC-verified slash-command listener.
- **#64** `wpsecscan digest schedule --weekly|--daily|--monthly` — schtasks + crontab template.
- **#65** Microsoft Teams notify upgraded from legacy MessageCard → Adaptive Cards 1.5.
- **#66** Bundled Datadog + New Relic dashboard JSON templates (`wpsecscan dashboard-templates ...`).
- **#67** `--push-redmine` / `--push-bugzilla` / `--push-trac` push functions in `issue_push.py`.

### Added — Phase I: credentials (items 68–72)

- **#68** `wpsecscan creds add SITE_URL` interactive prompt → OS keychain or sealed fallback.
- **#69** `creds {get,list,rm,rotate,use}` full CRUD; `creds use` prints POSIX exports for `eval`.
- **#70** `wpsecscan sso configure --type {oidc,saml} ...` — daemon SSO writer.
- **#71** Multi-account via `--account NAME` (field-suffix in storage).
- **#72** `wpsecscan hwkey {enable,disable,status,grant}` — gate `--aggressive` on token-or-typed-YES.

### Added — Phase J: workflow / orchestration (items 73–80)

- **#73** `wpsecscan cron-schedule {add,list,rm,run,trigger}` — POSIX cron-style absolute-time scheduler.
- **#74** `wpsecscan sla report URL` — finding-level open-days tracker + per-severity SLA breach detector.
- **#75** `--ai-auto-snooze-info-findings` + `--ai-flag-anomalies-for-human`.
- **#76** `wpsecscan import-pentest FILE` — Burp Suite scan XML + OWASP ZAP report.xml importer.
- **#77** `wpsecscan scan-zip plugin.zip` — pre-install static malware/vuln pattern scanner.
- **#78** Chrome MV3 + Firefox browser extension for wp-admin overlay (`browser-extension/`).
- **#79** `wpsecscan reference-diff` — diff live file-monitor manifest against clean WordPress archive.
- **#80** `wpsecscan mobile-api` — installable PWA + REST for phone dashboards (scope-down from native iOS/Android).

### Scope-downs documented in commit messages

- **#46** drag-drop URL/HAR intake (Tk lacks portable drag-drop).
- **#48** reference-install compare in GUI (CLI landed at #79 instead).
- **#49** HAR Repeater in GUI.
- **#56** centralised marketplace (ships scaffold + manual marketplace.json publish).
- **#61** Loki + Beats as helper-protocol forwarders (protocols differ enough to need separate testing).
- **#72** full FIDO2/WebAuthn CTAP (lands later; token-or-typed-YES is the practical gate today).
- **#80** native iOS/Android app (PWA + REST is the ship-today version).

### Notes

- `pyproject.toml` / `__init__.py` / `installer/wpsecscan-setup.nsi` all bumped to 2.5.0.
- `wp-plugin/wpsecscan-companion` bumped to 1.2.0 (12 new endpoints + admin UI changes).
- No public-API breaking changes: every new flag is opt-in; legacy `notify_teams` MessageCard
  → Adaptive Card change is invisible to receivers (Teams renders both).

## [v2.4.0] — 2026-05-26

Tests: **665 → 667 passing**. Phase A→F of the 66-item second-audit
delivery + the two previously-deferred GUI items (#51 pause/resume,
#56 minimize-to-tray) + distribution wiring (Docker, Homebrew, Scoop,
winget, PyPI Trusted-Publisher workflow).

**Headline:** the 66-item forward-looking audit completed in this
release ships ~50 new code paths (10 new check files, 1 companion-
plugin minor version, 7 new CLI subcommands, 2 new reporters, a
VS Code extension, policy engine, direct issue-tracker push, GitHub
PR commenter) plus pause/resume + tray icon for the GUI and the
release-distribution machinery for PyPI, Homebrew, Scoop, winget,
and Docker.

### Added — Phase A: detection (items 1–27)
- **#1** WC-context Stripe pk_live escalation — bump severity from
  low → medium when the key appears alongside WooCommerce markers
  on /cart/, /checkout/, /shop/ pages.
- **#5** Five new secret regexes: Mapbox secret + public tokens,
  Algolia admin API key (context-gated), MeiliSearch master key
  (context-gated), Sentry DSN, New Relic browser license key
  (context-gated). New CONTEXT_GATES dict so future regexes can
  register surrounding-text gates with one line.
- **#6** `referenced_buckets` check — extract bucket URLs referenced
  in HTML/JS and probe each for an open listing across S3, GCS, R2
  (.r2.dev + .r2.cloudflarestorage.com), and DigitalOcean Spaces.
- **#2** `cloudflare_origin_leak` — crt.sh transparency-log subdomains
  + bypass-prefix DNS guesses + MX-record reverse-resolution. Inline
  Cloudflare IP-range table; uses only free sources (no Censys/Shodan).
- **#4** `crlf_location_injection` — passive CRLF-in-Location probe at
  common WP redirect parameters (`redirect_to`, `returnurl`, `next`,
  `url`). Inspects ONLY the response Location/Set-Cookie headers.
- **#7** `host_header_validation` — DNS-rebinding susceptibility on
  admin endpoints (distinct from the existing `dns_rebinding` check
  which probes outbound SSRF rebinds).
- **#8** MTA-STS + TLS-RPT + BIMI detection added to `dns_security`.
- **#9** DNSSEC DS + DNSKEY chain check via dnspython (skips with an
  info finding when dnspython isn't installed).
- **#15 + #16** `woocommerce_storefront` — coupon-enumeration throttle
  probe + fragments-endpoint cacheability inspection.
- **#18** `page_builder_cve` — Bricks/Beaver/Divi/WPBakery/Oxygen/Brizy
  fingerprint + per-builder known-CVE family hint.
- **#19 + #20** `wp_fork_detection` — classify ClassicPress / Bedrock /
  headless-Next/Gatsby/Frontity; writes ctx['shared']['wp_fork'].
- **#21 + #22** `tls_modern` — TLS 1.3 0-RTT replay risk + OCSP stapling
  + must-staple via `openssl s_client` (falls back to a pure-Python
  handshake when openssl isn't on PATH).
- **#23-27** Companion plugin **v1.1.0** with 5 new REST endpoints
  (`/failed-login-geo`, `/admin-login-sources`, `/backups`,
  `/file-perms`, `/2fa-enforcement`) + scanner-side `companion_advanced`
  check that consumes all five in parallel with a cached Tor exit-node
  list. Token model upgraded to 10-use window so a single scan can
  pull all 9+ endpoints without re-prompting.
- Re-verified during the pass; SKIPPED as already shipped: **#3**
  (`smuggling_probe`/`http2_smuggling`), **#10** (`http_methods`),
  **#11** (`wpgraphql` introspection), **#12** (`rest_api` settings
  endpoint), **#13** (`backup_file_fuzz` wp-config variants), **#14**
  (`wp_salts_age` nonce-collision detection).

### Added — Phase B: operator workflow (items 28–42)
- **#28** `wpsecscan watch URL` — delta-only polling daemon with
  optional Slack webhook + --exit-on-new CI tripwire.
- **#29** `wpsecscan refix CHECK_ID URL` — re-run a single check and
  write a fix-attested receipt to `~/.wpsecscan/refix/`.
- **#30** `wpsecscan portfolio [--tag FOO]` — bulk-scan every site in
  sites.json with one agency dashboard + per-site exec PDFs.
- **#31** Site tags — `sites add --tag client:acme` + `sites list --tag`.
- **#32 + #34** `wpsecscan snooze {list|import|clear}` — surfaces the
  existing snooze data model + bulk-import from CSV.
- **#33** `wpsecscan diff-tree URL` — ASCII chronology of finding
  deltas across the last N snapshots.
- **#35** Direct REST push to Jira / Linear / ServiceNow / GitHub
  Issues. `~/.wpsecscan/issue-tracker-cache.json` keyed by
  sha256(target | check_id | finding_title) so re-scans don't dup
  tickets. ServiceNow gets a new payload generator that creates
  `incident` records.
- **#36** `wpsecscan pr-comment PR_URL` — walks a GitHub PR's file
  list and posts (or PATCHes a marker-keyed) summary comment with
  open CVEs for any plugin/theme touched in the diff. Uses
  $GITHUB_TOKEN; no GitHub App needed.
- **#37** VS Code extension (`vscode-extension/`) — sidebar findings
  tree + native Diagnostics + workspace auto-discovery.
- **#38** HMAC-SHA256 signing on outgoing webhooks
  (X-WPSecScan-Signature + X-WPSecScan-Timestamp).
- **#39** PagerDuty Events v2 + Opsgenie Alerts API integrations
  (auto-fire when WPSECSCAN_PAGERDUTY_KEY / WPSECSCAN_OPSGENIE_KEY
  env vars are set).
- **#40 + #41** `~/.wpsecscan/policy.yml` (or .json) — per-site
  severity overrides + suppression rules; applied AFTER scan and
  BEFORE reporters so the console and every output agrees.
- **#42** `waf_lockout_guard` check — early-abort + critical finding
  when the WAF blocks the first probe (avoids escalating to a
  permanent IP-ban).

### Added — Phase C: reports (items 43–50)
- **#43 + #45** Mobile-responsive HTML report + print-perfect CSS
  (page margins, hyperlink expansion, force-light backgrounds,
  break-inside:avoid).
- **#44** OS prefers-color-scheme honoured when the user hasn't
  manually toggled.
- **#46** `reporters/snapshot_compare.py` — three-column HTML view
  (Fixed / Unchanged / New) for two snapshots of the same site.
- **#47** Curated remediation videos under `data/remediation_videos.json`;
  HTML reporter embeds a "📺 N min" link beneath each matched finding.
- **#48** DOCX report (uses python-docx when installed; falls back
  to RTF). New `--docx` CLI flag.
- **#49** Risk-score trend chart in the executive PDF (PNG via PIL
  in the reportlab path; inline SVG polyline in the HTML-fallback
  path).
- **#50** `wpsecscan publish URL` — generate a static HTML scan
  receipt with HMAC-signed JSON-LD; the user uploads to their site
  and links from their footer.

### Added — Phase D: GUI (items 52–55, 57)
- **#52** Right-click → "Never run this check again" — writes to
  `~/.wpsecscan/disabled_checks.json`.
- **#53** Tools → Snapshot diff (same site, two scans) — Tk file
  pickers + `snapshot_compare` render in browser.
- **#55** File → Open saved JSON report (Ctrl+O) — load a previously
  saved scan without re-scanning.
- **#57** Keyboard-only operation: added Ctrl+O / Ctrl+S /
  Ctrl+Shift+E / Ctrl+D / Ctrl+P bindings.

### Added — Phase E: robustness (items 58, 60–62)
- **#58** HTTP retry with jittered exponential backoff on transient
  errors (TimeoutException + ConnectError) for idempotent GET/HEAD;
  POST/PUT/DELETE stay single-attempt to avoid double-applying state.
- **#60** Pre-flight WAF auto-derate — when --aggressive AND the
  apex resolves into a CF/Sucuri/Wordfence/Akamai/Imperva fingerprint,
  downgrade to passive scanning. Override with
  `WPSECSCAN_OVERRIDE_WAF_DERATE=1`.
- **#61** `--redact-evidence` CLI flag — mask JWTs, WP session
  cookies, bearer tokens, X-WPSecScan-Token header values, plus
  the existing PII (email/IP/cards/AWS/Google/Stripe/GitHub PAT/SSN)
  in evidence + remediation BEFORE any reporter writes.
- **#62** Signed snapshots — `save_report_snapshot` now writes
  `{snap}.json.sig` with HMAC-SHA256; `history.verify_snapshot()`
  re-computes on read and detects tampering.

### Added — Phase F: distribution (items 63–66)
- **#64** Docker — Dockerfile now installs from `pyproject.toml`
  (was broken — referenced a non-existent requirements.txt), pulls
  optional extras (dnspython, python-docx, reportlab, pillow),
  runs as a non-root user, uses tini as PID 1.
- **#65** Homebrew formula, Scoop manifest, winget manifests under
  `packaging/{homebrew,scoop,winget}/`.
- **#66** `.github/workflows/pypi-publish.yml` — TestPyPI dry-run
  + real-PyPI publish via PyPI Trusted Publisher (OIDC, no stored
  tokens). Triggered manually via workflow_dispatch.

### Added — Deferred items now shipped
- **#51** GUI pause/resume — Pause button + Ctrl+P. Coarse pause
  between checks (mirrors `is_cancelled` exactly). Cancel
  short-circuits any active pause to prevent the abort path
  from deadlocking.
- **#56** Minimize-to-tray — pystray + procedural PIL icon. Optional;
  `pip install wpsecscan[ui]` to enable. Pure UX affordance; no
  IPC with the `watch` daemon.

### Skipped
- **#3, #10, #11, #12, #13, #14** in Phase A — already shipped
  previously. Honestly noted in commit messages.

### Other
- README badges bumped: 187 → 200+ checks, 598 → 667 passing tests.

### Added (Round-65 — Group C (AI triage) + opt-in analytics → v2.3.0)

Tests: **646 → 665 passing**.

**Headline:** Round-65 ships the previously-deferred Group C (10
AI-triage features) behind an explicit opt-in panel — every feature
defaults to OFF and only becomes available when the user (a) has an
LLM backend configured (OpenAI / Anthropic / Ollama) AND (b) ticks
the feature in `Tools → Advanced AI options...`. Round-65 ALSO adds
the user-requested **opt-in, transparent, local-first usage
analytics** — also default OFF, also fully inspectable.

#### Group C — Advanced AI triage features (off by default)
- `wpsecscan/ai_triage.py` — 10 features + per-feature toggles
  persisted at `~/.wpsecscan/ai_settings.json`:
  - **C1** Severity auto-tuner — re-rank findings by site-specific real-world risk
  - **C2** Duplicate / sibling collapser — group N findings into K root causes
  - **C3** False-positive predictor — auto-hide above configurable threshold
  - **C4** Plain-English exec brief generator (audience: CEO/CTO/auditor/dev)
  - **C5** Remediation step-generator tailored to the user's stack
  - **C6** Forensics timeline narrator
  - **C7** Business-impact estimator (BYO revenue + tx context)
  - **C8** Ticket auto-gen (Jira / Linear / GitHub Issue shape)
  - **C9** Real-time CISA-KEV correlation per CVE
  - **C10** Conversational scan-result Q&A
- `wpsecscan/ai_triage_ui.py` — settings panel (GUI Toplevel) +
  `wpsecscan ai-options [list|get|set]` CLI subcommand
- GUI: new menu entry `Tools → Advanced AI options...`
- PII masking via existing `ai_safety.safe_for_llm()` is always-on
  for every AI-triage call

#### Opt-in usage analytics (off by default)
- `wpsecscan/analytics.py` — record `cli_command`, `check_ran`,
  `gui_action`, `feature_used`, `report_export` events with a
  **per-event field allowlist** (defence in depth against PII leaks)
- Counts are bucketed (`0` / `1-5` / `6-25` / `26-100` / `101-500` /
  `500+`) so individual scans can't be fingerprinted
- **Anonymous ID** is a UUID rotated every 90 days, never derived
  from hostname / IP / username
- **Local-first**: events go to `~/.wpsecscan/analytics/events.jsonl`;
  upload requires BOTH `WPSECSCAN_ANALYTICS_UPLOAD_URL` AND explicit
  opt-in
- New CLI: `wpsecscan analytics [status|enable|disable|show|export|forget]`
- New GUI entry: `Tools → Usage analytics options...`
- New doc: `docs/analytics.md` documents every promise + the source-
  code review checklist
- Local log capped at 10 MB with rolling .1/.2/.3 archive files

#### Privacy posture

The analytics system is explicitly designed to honour the v2.1.0
promise ("Zero telemetry — nothing flows back about who runs it").
Default behaviour is unchanged: nothing is recorded, nothing is
uploaded. The new code is dormant unless the user actively turns it
on, with full visibility into every event before it's uploaded.

### Added (Round-64 — 165 features across 18 groups → v2.2.0)

Tests: **607 → 646 passing**. Checks: **161 → 189**.

**Headline:** WPSecScan now ships **active exploit verification** (with
strict consent gating), **continuous monitors** (CT / DNS / WHOIS /
RBL / honeypot / auto-rollback), **threat-intel federation** to 10
upstream providers (CISA KEV / EPSS / Exploit-DB / Metasploit / MITRE
ATT&CK Navigator / STIX / MISP / OpenCTI / OTX / GreyNoise), every
release is **SLSA L3 signed** with cosign + CycloneDX SBOM, plus 26
new attack-surface checks (modern WP / Web3 / NFT / payment), 14 GUI
polish features, 7 new reporters, enterprise scaffolds (OIDC + SAML +
RBAC + audit-log + approval-workflow + multi-tenant + quota + billing),
and a full distribution-channel matrix (Docker, K8s, Homebrew, Snap,
Flatpak, winget, AUR, Chocolatey).

#### Group A — Active exploit verification (#1-10)
- `wpsecscan/exploit_verify.py` with strict consent gate
  (`WPSECSCAN_OWNED_TARGETS=1` AND target in sites list)
- 10 verifiers: poc-for-cve, exploit-chain, race/TOCTOU upload,
  stored-then-replay, SSRF OOB, JWT alg=none, CSRF token reuse,
  smuggling chain, pre-auth RCE, wpcron inject

#### Group B — Continuous monitoring (#11-20)
- `wpsecscan/monitors.py` — 10 monitors with persistent state at
  `~/.wpsecscan/monitors/<name>.json`
- Live attack feed, Certificate Transparency watch, DNS/WHOIS-change,
  dark-web mention, RBL reputation, CISA KEV match, GeoIP anomaly,
  honeypot hits, auto-rollback

#### Group D — Trust signals (#31-40)
- `.github/workflows/release-attestation.yml` — SLSA L3 + cosign
  keyless + CycloneDX SBOM
- `.github/workflows/ossf-scorecard.yml` — weekly OpenSSF Scorecard
- `.well-known/security.txt` (RFC 9116)
- `SECURITY-ACK.md` — researcher hall of fame
- `BUG-BOUNTY.md` — self-funded bounty
- `docs/verify-release.md` — full verification guide

#### Group E — Threat-intel integrations (#41-50)
- `wpsecscan/threat_intel_v2.py` — 10 TI providers with TTL cache
- CISA KEV / EPSS / Exploit-DB / Metasploit / MITRE ATT&CK Navigator
  layer / STIX 2.1 bundle / MISP / OpenCTI / AlienVault OTX /
  GreyNoise + unified `enrich_finding()`

#### Group F — Modern WP attack surface (#51-70) — 20 new checks
1. `ai_prompt_injection_passive` 2. `wpconfig_hardening_audit`
3. `db_trigger_audit` 4. `postmeta_stored_xss_scan`
5. `vendor_backdoor_patterns` 6. `cryptominer_js_injection`
7. `magecart_skimmer_patterns` 8. `plugin_typosquat_detection`
9. `composer_lock_audit` 10. `package_lock_audit`
11. `yarn_pnpm_lock_audit` 12. `rest_app_passwords_enum`
13. `mfa_priv_account_audit` 14. `wpcron_suspicious_jobs`
15. `webhook_url_fingerprint` 16. `git_dir_deep_scan`
17. `env_file_enum` 18. `helm_compose_leak`
19. `tailwind_css_comment_leak` 20. `graphql_field_authz_deep`

#### Group G — Web3/NFT/payment (#71-76) — 6 new checks
- `web3_wallet_connector_audit`, `nft_mint_pubapi`,
  `crypto_payment_callback_audit`, `solidity_abi_leak`,
  `wallet_seed_phrase_leak` (BIP-39 dictionary scan),
  `payment_gateway_test_keys` (test-key-on-prod detection)

#### Group H — UX dashboard polish (#77-90)
- `wpsecscan/gui_round64.py` — 14 helpers: real-time progress,
  click-through fix panel, diff vs last scan, severity pie, saved
  filter views, dark/light theme, shortcuts panel, 7-day snooze,
  bulk export, in-app changelog, drag-drop import, scan-all button,
  pystray tray notifications

#### Group I — Reports & sharing (#91-97) — 7 new reporters
- `badge_svg`, `public_page` (opt-in), `pdf_custom_branding`,
  `eli5_toggle`, `comparison_two_sites`, `trend_over_time` (SVG
  sparkline), `translated_summary` (en/es/de/fr/ja/zh)

#### Group J — Mobile + accessibility (#98-103)
- React Native + Capacitor mobile scaffolds (docs)
- `a11y_wcag_aaa` check (WCAG 2.2 AAA extras)
- CLI `--screen-reader`, `--high-contrast`, `--voice-summary` flags
- `docs/keyboard-only-walkthrough.md`

#### Group K — Distribution (#104-113)
- Dockerfile refreshed for AGPLv3 + v2.2.0
- k8s operator scaffold + Homebrew/Chocolatey/Snap/Flatpak/winget/AUR
  + `docs/install-matrix.md`

#### Group L — Enterprise (#114-122)
- OIDC + SAML SSO scaffolds
- Reader/Operator/Admin RBAC
- HMAC-chained audit log + chain verifier
- Two-person approval workflow
- White-label branding
- Multi-tenant namespacing + per-tenant quotas + Stripe metered
  billing stub

#### Group M — Community (#123-132)
- Opt-in public scan DB schema (PII-free)
- Check marketplace design, Discord bot stub, ROADMAP.md,
  newsletter template, contributor leaderboard + script, check
  voting schema, scan-buddy pairing program, GH Discussions setup

#### Group N — IaC (#133-140)
- Terraform provider stub, Ansible role, Pulumi component,
  HashiCorp Sentinel policy, ServiceNow import set, Datadog Agent
  check, Grafana dashboard, Prometheus exporter

#### Group O — SDKs + API (#141-147)
- Python / TypeScript / Go SDKs
- OpenAPI 3.1 spec + Postman collection
- `webhook_v2` (HMAC + nonce + replay window)
- `docs/api-reference.md` full reference

#### Group P — Check authoring (#148-152)
- `scripts/new-check.py` interactive scaffolder
- `scripts/lint-checks.py` AST-based hygiene linter
- `tests/check_framework.py` shared fixtures
- `docs/writing-a-check.md` tutorial
- `wpsecscan/checks/_template.py` skeleton

#### Group Q — Education (#153-159)
- CTF round 1, MOOC outline, cert program design, webinar template,
  State of WP Security 2026 outline, WP-security-101, IR runbook

#### Group R — Performance (#160-165)
- Redis-queue distributed coordinator
- ARM64 build instructions
- ETag-based incremental diff scan
- Precondition-based smart-skip
- Parallel-sites fan-out
- Shared httpx.AsyncClient pool

#### Wild cards (#166-175)
- Chrome/Firefox WebExtension, Slack + Teams bots, WP Security Bingo,
  brand-monitor check, Wayback historical scanning, global
  leaderboard opt-in, wp-cli bridge, auto-isolation, forensics
  timeline builder

#### Compatibility note
- Original `wpsecscan/{incremental,perf,daemon}.py` modules moved
  into matching package dirs as `_legacy.py` and re-exported from
  each `__init__.py`. All prior import paths continue to work.

### Added (Round-63 — multi-source CVE aggregator → v2.1.0)

Tests: **590 → 607 passing**.

**Headline:** WPSecScan now runs its own nightly CVE aggregator that
pulls from **8 free sources** and serves a single deduped feed — users
get a strictly more complete + fresher database than any single paid
or free service provides.

#### Why this round shipped

- Wordfence's free v2 Intelligence scanner endpoint was discontinued
  (returns HTTP 410); v3 now requires a Wordfence Cloud account.
- Users running `wpsecscan db update` against Wordfence directly were
  starting to see empty refreshes.
- Solution: aggregate from **8 free sources** every night, dedupe,
  publish to a `data-feed` branch users can pull from.

#### The 8 sources
1. **Wordfence Intelligence v3** (when key set; partial-free)
2. **OSV.dev** Packagist ecosystem (fully free, CC-BY-4.0)
3. **GitHub Security Advisories** GraphQL (fully free, CC0)
4. **Mitre CVE List V5** canonical (fully free, CC0)
5. **NVD National Vulnerability Database** (fully free, CC0 US gov)
6. **WPVulnerability.com** community DB (fully free, CC-BY-SA)
7. **Patchstack public RSS** (fail-soft — currently down upstream)
8. **CIRCL CVE-Search** EU mirror (fully free)

**Net: 6 of 8 are fully free, no key required.**

#### New files
- `scripts/aggregate-cve-feed.py` — 700-line aggregator with per-source
  error tolerance, regex-validated input, symlink guards, dedupe by
  `(type, slug, cve)` keeping the highest-CVSS entry per key
- `.github/workflows/cve-feed.yml` — nightly cron at 02:00 UTC,
  commits merged JSON to `data-feed` branch
- `docs/data-sources.md` — full per-source documentation (licence,
  rate limit, coverage, opt-out env vars)

#### Modified files
- `wpsecscan/db.py`:
  - New `AGGREGATED_FEED_URL` constant (override via `WPSECSCAN_AGGREGATED_FEED_URL`)
  - New `fetch_aggregated()` function pulls our merged feed in one round-trip
  - New `cached_sources()` reads per-source contribution from the cache
  - `save_cache()` now persists `_sources` field
  - `update_db()` reordered: aggregated feed first, Wordfence-direct fallback,
    OSV final fallback (defence in depth)
- `wpsecscan/__main__.py`:
  - New `wpsecscan db source-stats` action — prints per-source
    contribution table from the local cache

#### QA fixes (caught during round-63 build)
- aggregator Unicode arrow `→` replaced with `->` for Windows cp1252 compat
- `datetime.utcnow()` → tz-aware (deprecation)
- Patchstack RSS fetcher fail-soft when endpoint returns HTML
- Mitre CVE-List fetcher honours `GITHUB_TOKEN` (raises rate limit
  from 60/hr to 5000/hr)
- `db.py` Vuln rehydration provides defaults for aggregator-missing fields
- 17 new tests in `tests/test_round_63.py`

### Added (Round-62 — 89-feature mega-round → v2.0.0)

Biggest round yet. Inventory: **154 → 161 checks**. Tests: **542 → 585 passing**.
Version bumped to **v2.0.0** to reflect cumulative scope across rounds 54-62.

#### Scanner checks (B21-B38) — 7 new modules
- `server_stack_reveal` — banner-header inventory + PHP/nginx/Apache EOL detection
- `waf_brand_deep` — fingerprints 11 commercial WAFs
- `sri_audit` — Subresource Integrity check on every cross-origin resource
- `service_exposure` — TCP probe on 14 well-known DB/cache/admin ports (RFC1918 auto-skipped)
- `js_framework_deep` — version-pin check for 12 SPA frameworks
- `sri_pwa_misc` — SameSite=None / WebDAV LOCK / PWA / HTTP/3 / contrast bundle
- `wp_cli_inject` — wp-cli.phar exposure + shell-exec hunt

#### Reporting (C39-C50) — 12 export formats in `reporters/round62.py`
PowerPoint .pptx · Word .docx · JIRA bulk-create · Confluence markdown ·
Streamlit dashboard · Grafana JSON · SIEM NDJSON (Splunk HEC / Elastic / Loki)
· Datadog JSON · CSV pivot · SBOM diff · SBOM VEX/VDR · Quarterly trend PDF

#### Integrations (D51-D60) — 10 in `integrations/round62.py`
Burp project XML · ZAP findings import · Nuclei template auto-pull ·
Wordfence Cloud sync · Sucuri SiteCheck · Patchstack write-back ·
WPScan write-back · WP Engine / Kinsta / WP.com host APIs · n8n recipes ·
VS Code scaffold

#### Workflow + Defensive (E61-E70 + G78-G80) — 13 in `round62_workflow.py`
Daily digest · PR-comment markdown · pre-commit hook · watch mode ·
companion log tail · Apple Shortcuts · browser bookmarklet · zsh completion ·
man page · auto-resume marker · SIEM live forwarder · honeypot deploy guide ·
egress recorder (in `egress_recorder.py`, capped at 50 MB)

#### Distribution manifests (F71-F77)
Chocolatey · Winget · Homebrew · Snap · Flatpak · AppImage · per-platform docs

#### New tooling modules
- `wpsecscan/egress_recorder.py` — every outbound IP logged (50 MB cap, rollover)
- `wpsecscan/network_fingerprint.py` — JA3/JA4-lite TLS fingerprint
- `wpsecscan/round62_workflow.py` — workflow + defensive bundle

#### GUI integration (D1-D9, A1-A20)
6 new Tools-menu entries (DB status / Sites dashboard / CVE subscriptions /
Proxy settings / User mode / Report a bug) with safe handler methods that
tolerate missing modules. Foundations from round-61 (Sun Valley theme,
config persistence) still apply.

#### QA fixes (caught before push)
- `gui.py:_open_db_status` — removed dead `if "os" in dir()` check
- `checks/service_exposure.py` — added RFC1918 auto-skip (`WPSECSCAN_SCAN_LAN=1` to override)
- `egress_recorder.py:record()` — 50 MB cap with `.archived` rollover

### Added (Round-61 — plugin polish, auto-vuln-update, UI overhaul, proxy)

Tests: **513 → 542 passing**. Five focused-improvement areas you asked
about after v1.9.0 shipped.

#### Q1 — WP companion plugin: wp.org-submission-ready
- `wpsecscan-companion.php`: added `Domain Path: /languages` header
- `wpsecscan-companion.php`: added `load_plugin_textdomain()` on
  `plugins_loaded` hook
- `includes/rest.php`: removed insecure `?token=` query-param fallback
  (header-only enforcement)
- `includes/diagnostics.php`: `mysql_get_client_info()` →
  `mysqli_get_client_info()` (PHP 8+ compat)
- `readme.txt`: added FAQ (7 questions), Screenshots, Upgrade Notice sections
- New `wp-plugin/wpsecscan-companion/languages/` directory (i18n compliance)
- New `wp-plugin/wpsecscan-companion/assets/` with 5 placeholder PNGs
  (icon-128, icon-256, banner-772, banner-1544, 3 screenshots) via
  Pillow — see `scripts/gen-wp-plugin-assets.py`
- New `docs/wp-org-submission.md` — full SVN submission guide for the
  manual steps (account, slug request, asset upload, SVN dance)

#### Q5 — Private proxy support
- `wpsecscan/http.py:Client` now accepts `proxy=` + `proxy_auth=`
  kwargs and passes them to httpx (with httpx <0.26 / >=0.26 compat)
- New `_merge_proxy_auth()` helper — URL-encodes the password and
  injects into `scheme://creds@host:port` correctly
- `wpsecscan/scanner.py`: threads `proxy` / `proxy_auth` from ctx into
  `Client(...)`; resolves precedence (CLI flag → `WPSECSCAN_PROXY_URL` env)
- New CLI flags: `--proxy URL` + `--proxy-auth USER:PASS`
- Per-site proxy: `wpsecscan sites add URL --proxy ... --proxy-auth ...`
  — sealed at rest via existing `_seal()` (DPAPI/TPM/gpg)
- `WPSECSCAN_PROXY_AUTH` env var (matches existing `WPSECSCAN_PROXY_URL`)
- New `docs/proxy.md` — full SOCKS5/HTTP/auth/per-site guide

#### Q2 — Auto-update vulnerabilities
- New `wpsecscan db {status|update|subscribe|unsubscribe|signatures|alert-check}`
  CLI subcommand router
- `db.status()` — source / cache path / entry count / age / staleness
- `db.subscribe(webhook_url, site_url, label)` — webhook-fired alerts
  when a new CVE matches an installed plugin
- `db.unsubscribe()`, `db.subscriptions_load()` — manage subscriptions
- `db.refresh_exploit_signatures()` — pull exploit-signatures from
  GitHub raw without reinstalling the binary
- `db.load_exploit_signatures()` — prefers cached refresh over bundled
- New `watchers.cve_alert_check()` — runs on the scheduled DB-refresh
  task; diffs installed plugins per site against latest CVE DB; fires
  matching subscriptions; throttles repeat alerts via Merkle-style key list
- `sites.install_schedule()` now also registers a **daily 02:00 DB-refresh
  task** (alongside the weekly 03:00 scan task) on Windows / macOS / Linux
- `sites.uninstall_schedule()` removes both tasks
- New `docs/auto-update.md` — explains the 3 update layers + opt-out

#### Q4 — Advanced settings + Beginner/Standard/Expert mode
- New `wpsecscan/config.py` — persistent `~/.wpsecscan/config.json`
  with: theme, follow_os_theme, mode, last_url, show_welcome,
  proxy_url, proxy_auth, ai_opt_in, compliance_framework
- Helpers: `config.is_expert()`, `is_beginner()`, `effective_theme()`
  (auto-detects OS dark mode), `reset()`
- Foundations laid; GUI integration of mode picker + tabbed Settings
  deferred to a follow-up Tk-render-tested round to avoid GUI regressions

#### Q3 — UI polish
- New `gui_polish.apply_sv_ttk_if_available()` — Sun Valley ttk theme
  (Windows 11 look) when `sv-ttk` is installed; falls back to existing
  clam theme otherwise
- New themes: `sv-ttk-dark`, `sv-ttk-light` (auto-applied when
  `follow_os_theme=True` in config)
- `pyproject.toml`: added `[ui]` optional extra (`sv-ttk>=2.6`, `Pillow>=10`)
  + included in `[all]`

#### QA pass fixes (from round-61 audit, before commit)
- `db.load_exploit_signatures()` — clarified symlink-skip logic
- `sites._install_macos()` + `_install_linux()` — added symlink guards
  before writing plist/timer files
- `sites._install_macos_db()` + `_install_linux_db()` — same symlink guards
- `config.effective_theme()` — narrowed exception catch from
  `(ImportError, Exception)` to `(ImportError, AttributeError, OSError)`

### Added (Round-60 — 28 features + WP companion plugin + AGPLv3 relicense)

Big-impact round. Inventory: **150 → 154 checks**. Tests: **485 → 513 passing**.

#### License switch (Q2)
- **LICENSE switched from MIT → AGPLv3+** (v1.9.0 onward; older releases stay MIT)
- New `NOTICE` file with the AGPL network clause + commercial licensing note
- Optional PyArmor obfuscation wrapper (`scripts/build-obfuscated.py`)
- Offline-friendly license-key system (`wpsecscan/licensing.py` + Ed25519 keypair generator)

#### New checks (Q4 — 4 new + 24 tooling features)
- `wp_multisite_deep` (#17) — per-blog deep audit + cross-tenant leak probe
- `honeypot_admin` (#19) — honeypot / anti-spam plugin detection
- `a11y_deep` (#24) — full WCAG 2.2 audit (8 criteria)
- `perf_budget` (#25) — TTFB / HTML weight / render-blocking CSS / 3p-script count

#### New tooling modules (Q4 — features that aren't "checks")
- `editor/browser-extension/` (#2) — Chrome/Firefox right-click launcher
- `integrations/webhooks_chat.py` (#3) — Slack / Discord / Teams alerters
- `editor/mobile-app/` (#4) — read-only mobile companion blueprint
- `.github/actions/wpsecscan/action.yml` (#5) — composite GitHub Action
- `round60.py` (#6-8, #10-13, #16, #21, #27) — public history page, diff_reports, PDF-with-logo, marketplace patch lookup, time-machine replay, side-by-side compare, RateLimit context-mgr, HackerOne/Bugcrowd autofill, Terraform/Ansible emit, lockout-recovery via ssh
- `auto_remediation.py` (#9, #18) — companion-plugin-driven safe auto-fixes
- `integrations/marketplace.py` (#10) — patched-in-vX.Y.Z lookup
- `integrations/tor_proxy.py` (#14) — SOCKS5 proxy + Tor exit check
- `screenshot.py` (#15) — already existed, kept
- `integrations/ticketing.py` (#20) — Jira / Linear / GitHub Issues filing
- `integrations/threat_intel.py` (#22) — VirusTotal + GreyNoise enrichment
- `watchers.py` (#26-30) — wp_version_drift_alert, malware_scan_diff,
  dns_change_watcher, subdomain_takeover_scan, daemon-friendly

#### Bug-report system (Q4 user-asked)
- New `bug_report.py` — GUI "Report Bug" with system-info, redacted log,
  optional report attach, GH-Issues URL builder, opt-in GlitchTip POST,
  prior-crashes list with status tracking, send-feedback non-crash channel

#### WP companion plugin (Q8)
- New `wp-plugin/wpsecscan-companion/` PHP plugin
- Read-only REST endpoint `/wp-json/wpsecscan/v1/diagnostics`
- One-time token (hashed at rest, 60-minute expiry, single-use)
- HTTPS-only, no write actions, sanitised payload
- Returns: core, plugins[], themes[], users[], cron[], auth_filters,
  site_health, config_constants
- New `--companion-token` scanner flag — single-round-trip diagnostics
- `scripts/build-wp-plugin.py` produces wp.org-ready `dist/wpsecscan-companion.zip`

#### Weekly auto-scan + multi-site dashboard (Q6)
- New `sites.py` — persistent site list at `~/.wpsecscan/sites.json`
  (creds DPAPI/TPM-sealed where available)
- `wpsecscan sites add/list/remove/scan` subcommands
- `wpsecscan schedule install/uninstall/pause/resume` — Windows
  schtasks / macOS launchd / Linux systemd
- `wpsecscan digest configure/test` — weekly digest via SMTP / Slack

#### Improved WP admin login (Q7)
- `authenticated.py` rewritten — three flows:
  - WP Application Password (preferred, WP 5.6+)
  - Companion-plugin token (richest data)
  - Cookie + wp-login.php (fallback) — now with 2FA prompt handling
- New `--auth-app-password`, `--auth-totp`, `--companion-token` flags
- Authenticated checks expanded: REST users (emails + roles), HTML user
  HTML page, definitive plugin list, inactive themes (attack surface),
  Site Health critical issues, pending core/plugin/theme updates,
  dangerous options (default_role, users_can_register)

#### Windows installer (Q5)
- `installer/wpsecscan-setup.nsi` — NSIS wizard with:
  - Optional "Add to PATH"
  - Optional "Run GUI at Windows startup" (HKCU Run reg value, `--minimized`)
  - Optional "Register weekly auto-scan" (wraps `schedule install`)
  - Optional "Add Defender exclusion"
  - Uninstaller prompts before wiping `~/.wpsecscan/`
- `installer/wpsecscan.wxs` — MSI alternative for enterprise group policy

#### Docs (Q10)
- `docs/` directory — GitHub Pages-ready (Jekyll `_config.yml`)
- 11 hand-written guides: install, first-scan, auth, wp-plugin,
  weekly-scans, compliance, ai, ci, bounty, gui, plugin-authoring
- `scripts/generate-docs.py` — auto-generates `docs/checks/*.md` from
  every check's docstring (150+ pages produced)
- `docs/vs-wpsec.md` — competitor comparison

#### Cleanup (Q1)
- Stale `test-*` directories removed from repo root (20 dirs)
- `.editorconfig` added
- `py.typed` marker for downstream type inference
- `wpsecscan/__init__.py` version bumped 1.8.0 → 1.9.0

### Added (Round-59 — 111-feature mega-round, the best WordPress scanner)

The biggest single round yet — 111 features across 18 waves (A-R).
Inventory: **136 → 150 checks**. Tests: **427 → 485 passing**.

- **14 new check modules** (registered in `ALL_CHECKS`):
  - `wp_builder_audit` — block-theme/FSE + page-builder version pins (Elementor / Divi / Bricks / Oxygen)
  - `wp_form_audit` — CF7 / WPForms / Gravity / Ninja / Formidable / Fluent (REST + upload-dir leaks)
  - `wp_membership_lms_audit` — MemberPress / PMPro / RCP / LearnDash / LifterLMS / TutorLMS / Sensei
  - `wp_commerce_alt_audit` — EDD / WP eCom / Square / Bookly / Amelia / BookingPress / MotoPress
  - `wp_plugin_ecosystem_audit` — 28-plugin sweep (search/SEO/backup/SMTP/cache/CDN/sec/chat)
  - `privacy_inventory` — PII patterns + cookie banner + 3p JS + Google Fonts CJEU + GA anonymize_ip + RTBE
  - `email_security_deep` — DMARC progression, MTA-STS, BIMI, ARC, DKIM rotation, SPF 10-lookup, SPF macros
  - `dns_deep` — DNSSEC, CAA, TXT-secret, HTTPS SVCB, resolver fingerprint, glue, wildcard, PTR
  - `auth_modernisation` — passkey/WebAuthn detect, 2FA plugin sweep, SAML, OAuth/PKCE, JWT refresh, magic-link
  - `crypto_agility` — TLS 1.3 + PQ KEX hints, cert inventory, RSA <2048, curve preference
  - `cdn_edge_audit` — Cloudflare/CloudFront/Bunny/KeyCDN/Fastly/Akamai detection + Worker route + signed-URL bypass + origin-pull injection
  - `payment_commerce_deep` — Stripe/PayPal/Square + test-key leak + PCI 4.0 checklist + 3DS2 hint + Woo IDOR + PCI evidence JSON
  - `compliance_frameworks` — HITRUST / CMMC / NIST CSF 2.0 / CIS v8 / ISO 27001:2022
  - `headless_wp_audit` — WPGraphQL deep, Next.js/Gatsby, Bedrock, Atlas/WPE purge-token leak, REST permalink
- **8 new tooling modules** (not checks; pure helpers):
  - `ai_safety` (#68-72) — hallucination verify, cost tracking, llama.cpp backend, prompt-injection guard, PII masking
  - `ux_extras` (#74-82) — a11y audit, vim keys, power shortcuts, OS dark-mode, sound packs, quiet hours, stars, saved searches, Obsidian/Notion export
  - `plugin_outreach` (#83-86) — disclosure email, wp.org submission, Patchstack, CVE 5.1 record
  - `reliability` (#92-94) — per-check regression, per-target alerts, cache-trend 30-day
  - `browser_replay` (#95-97) — Playwright recorder, report diff, attacker-view MP4
  - `hardware_keys` (#98-100) — WebAuthn fido2, Yubikey GPG, TPM2/DPAPI sealing
  - `waf_tuning` (#101-104) — allow-list generator, CF API push, ModSec CRS export, log-only flip
  - `novel_research` (#105-109, 111, 112) — FP learner, honeypot detector, mutation testing, visual regression, X25519 sharing, remediation A/B, Merkle log
- **i18n expansion (#73):** built-in locales added — FR, DE, PT-BR, JA, ZH-CN (was en + es)
- **Compliance mapping v2 (`data/compliance_v2.json`):** 106-check mapping across HITRUST / CMMC / NIST CSF 2.0 / CIS v8 / ISO 27001:2022

### Fixed (during round-59 QA pass)

- `wp_membership_lms_audit` — removed dead `_probe()` / `ctx_url()` placeholder helpers
- `hardware_keys._PGP_KEY_RE` — tightened regex (was too permissive on email format)
- `integrations/osint.py` + `checks/upload_path_predictable.py` + `plugin_outreach.py` — `datetime.utcnow()` → timezone-aware `datetime.now(tz=timezone.utc)`
- All new modules verified for: `WPSECSCAN_NO_AI` short-circuit (every LLM path), symlink guard before file write, host-count caps, parameterised SQL (`novel_research`), no `shell=True` in subprocess calls

### Added (Round-58 — 117-feature mega-round, becoming the best WP scanner)
- **16 new checks** across 4 waves: WordPress deep dives (Gutenberg blocks,
  wp-cron DoS, REST permission audit, WP_Query SQLi, salt-age, Heartbeat
  abuse, WooCommerce deep, plugin-specific audit), cloud (`hosting_platform_audit`,
  `origin_ip_discovery`), exploit primitives (HTTP/2 smuggling, upload-bypass
  deep, misc-injection, TLS-reneg DoS, cache-poison v2), OSINT enrich.
  Inventory: **136 checks** (was 120).
- **12 new utility modules**: `risk_aging`, `continuous`, `ai_assist`
  (BYO key — OpenAI/Anthropic/Ollama), `perf` (BloomFilter / worker-pool /
  memoization), `gui_polish` (CyberChef/Shodan/tray/notify/themes/
  achievements), `observability` (self-health/profile/watchdog/tail),
  `scanner_security` (gpg-encrypt/shred/sandbox/sigstore/perms-audit),
  `education` (tutorial + CTF + plain-English), plus `integrations/osint`,
  `reporters/bounty_format`, `reporters/executive_pack`.
- **VS Code extension scaffold** (`editor/vscode/`), **pre-commit hook**
  (`scripts/pre-commit-hook.sh`), **cross-platform build recipes**
  (`ECOSYSTEM-INTEGRATIONS.md`).
- **HIPAA / FERPA / SOC 2 / FedRAMP / GDPR Article mappings** for 23
  check IDs (`data/compliance_extra.json`).
- **WPSECSCAN_NO_AI=1** env to hard-disable all AI features regardless of
  API-key presence (data-privacy guardrail).
- 35 new tests; total now **427 passing** (was 392).

### Fixed (Round-58 QA pass — 7 issues)
- `scanner_security.shred_older_than` — symlink guard prevents
  symlink-attack on shred dir.
- `continuous.discover_wp_in_cidr` — MAX_DISCOVER_HOSTS=256 hard cap;
  refuses /16 or larger.
- `gui_polish.desktop_notify` — XML escape (Windows toast) +
  AppleScript escape (macOS) on title/msg, preventing shell/markup
  injection from user-supplied strings.
- `reporters/bounty_format._safe()` — escapes `{`/`}` in finding fields
  so str.format() doesn't accidentally re-interpolate user content.
- `integrations/osint.find_bounty_program` — 24h disk cache + 0.4s pacing
  between HackerOne/Bugcrowd/Intigriti probes, avoiding rate-limit storms
  in batch scans.
- `ai_assist` — every entry point checks `WPSECSCAN_NO_AI` env first;
  data-warning added to `executive_summary` docstring.

### Added (Round-57 — competitor-parity, 40 features)
- **16 new checks** (wpscan/nuclei/ZAP/turbo-intruder parity): timthumb,
  plugin_hash_fingerprint, users_deep, plugin_archive_fuzz, premium_license_leak,
  xmlrpc_method_brute, yaml_templates, yaml_workflows, dns_templates,
  headless_templates, spider_crawl, forced_browse, websocket_fuzz,
  openapi_scanner, mobile_app_endpoints, host_recon. Inventory: **120 checks**.
- **21 new non-check modules**: ua_rotation, rate_limit, template_engine,
  workflow, interactsh, auto_scan, template_fuzz, template_signature, spider,
  scan_modes, session_context, alert_filters, js_plugin, turbo_engine,
  attack_scripts, response_diff, attack_checkpoint, burp_import, pcap_replay,
  mobile_app_discovery, intel_freshness.
- **GUI update-notice popup** at launch — shows "Update available" with a
  click-to-download button that opens the GitHub release page. Help → Check
  for updates now to force a re-check.
- **HTTP client `rotate_ua` flag** — opt-in per-request UA rotation from a
  20-entry realistic pool.
- **Marketplace remote-catalogue fetch** — static + remote (24h cached) merged.

### Fixed (Round-57 QA pass)
- `template_engine.py`: NameError on undefined `error` in exception tuple
  (referenced `re.error` without import alias).
- `headless_templates.py`: missing aggressive-mode gate — check ran in
  passive mode despite being registered as aggressive.
- `rate_limit.py`: unbounded module-global state dict; now LRU-capped at
  64 services with `clear()` helper.
- `turbo_engine.last_byte_sync`: socket leak when `connect()` failed
  after socket creation.
- `interactsh.py`: `WPSECSCAN_INTERACTSH_URL` env now rejects loopback /
  metadata / RFC1918 hosts (SSRF guard).
- `js_plugin.py`: stdout capped at 10 MB; runaway Node script can't OOM.
- `template_signature.py`: gpg stderr sanitised before embedding in return.

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
