# Changelog

All notable changes to WPSecScan are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
