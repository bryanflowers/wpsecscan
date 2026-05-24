# Changelog

All notable changes to WPSecScan are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
