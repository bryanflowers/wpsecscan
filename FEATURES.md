# WPSecScan — feature catalogue

A complete index of what this tool checks, what it outputs, what knobs you can turn, and what's deliberately out of scope.

For install instructions, see [README.md](README.md).

---

## Round-60 — 28 features + WP companion plugin + AGPLv3 relicense

v1.9.0. Inventory: **150 → 154 checks**. Tests: **485 → 513 passing**.

- **License switch**: MIT → AGPLv3+ (v1.9.0 onward). v1.0–v1.8 stay MIT.
  Adds network clause — SaaS deployments must publish their source.
- **WP companion plugin** (`wp-plugin/wpsecscan-companion`): token-gated
  read-only REST endpoint at `/wp-json/wpsecscan/v1/diagnostics` returning
  authoritative plugin/theme/user/cron/Site-Health data in one round-trip.
  No more HTTP-probe guessing.
- **Auth flow upgrade**: WP Application Password (preferred) + 2FA TOTP
  handling + companion-plugin token + cookie fallback. 7 authenticated
  checks: REST users, plugin list, theme list, Site Health critical,
  pending updates, dangerous options.
- **Weekly auto-scan + dashboard**: `wpsecscan sites/schedule/digest`
  subcommands. Windows Task Scheduler / launchd / systemd integration.
  Email + Slack/Discord/Teams digest.
- **Windows installers**: NSIS wizard (with autostart + scheduler +
  Defender-exclusion options) + WiX MSI for enterprise group policy.
- **Bug-report system**: GUI "Report Bug" → pre-filled GH issue with
  redacted log + system info. Opt-in GlitchTip/Sentry POST. Prior-crash
  list with status.
- **28 new features** (Q4):
  - **Checks**: wp_multisite_deep, honeypot_admin, a11y_deep (WCAG 2.2),
    perf_budget
  - **Tooling**: browser extension, mobile app blueprint, GitHub Action,
    Slack/Discord/Teams webhooks, public-history page, PDF with company
    logo, marketplace patched-in lookup, time-machine replay, side-by-side
    compare, RPS limiter, Tor/SOCKS proxy, screenshot per finding,
    HackerOne/Bugcrowd autofill, ticketing integrations (Jira/Linear/GitHub),
    threat-intel (VirusTotal/GreyNoise), Terraform/Ansible emit, lockout
    recovery via wp-cli, WP version drift watcher, malware-scan diff,
    DNS change watcher, subdomain takeover monitor, auto-remediation
- **Docs site**: `docs/` is GitHub-Pages ready. Auto-generated per-check
  pages (150+). Hand-written guides for install, auth, weekly scans,
  AI, CI, bounty, GUI, plugin authoring.
- **Repo cleanup**: 20 stale `test-*` directories removed; `.editorconfig`,
  `py.typed` added.
- **License-key system + optional PyArmor obfuscation** (operator-only).

---

## Round-59 — 111-feature mega-round (the best WordPress scanner)

The biggest single round yet — 111 features across 18 waves (A-R).
Inventory: **136 → 150 checks**. Tests: **427 → 485 passing**.

Highlights (full list per category below; see CHANGELOG.md for every item):

- **Wave A — WP vertical plugins (#1-15):** block-theme/FSE audit, page-builder
  CVE pins (Elementor/Divi/Bricks/Oxygen…), form-plugin deep (CF7/WPF/GF/NF),
  membership + LMS audit (MemberPress/LearnDash…), alt-commerce + booking
  (EDD/Bookly/Amelia), and an 8-ecosystem plugin sweep (search/SEO/backup/SMTP/
  cache/CDN-plugin/sec/chat) catching directory-listing leaks of UpdraftPlus,
  Easy WP SMTP debug logs, W3TC master configs, etc.
- **Wave B — Privacy/GDPR (#16-23):** PII inventory, cookie-banner detection,
  third-party JS exfil + DPA helper + jurisdiction guess, Google Fonts CJEU,
  GA anonymize_ip, RTBE endpoint probe.
- **Wave C — Email deep (#24-31):** DMARC progression, MTA-STS, BIMI, ARC,
  DKIM rotation hints, SPF 10-lookup count, SPF macros, open-relay guidance.
- **Wave D — DNS deep (#32-39):** DNSSEC, CAA, TXT-secret-scan, HTTPS SVCB,
  resolver fingerprint, glue records, wildcard, PTR.
- **Wave E — Auth modernisation (#40-46):** passkey/WebAuthn, TOTP plugin
  sweep, SAML, OAuth2/PKCE, JWT refresh, session-cookie hardening, magic-link.
- **Wave F — Crypto agility (#47-51):** post-quantum, TLS 1.3, crypto
  inventory, RSA <2048 bit, curve preference.
- **Wave G — CDN/edge (#52-57):** Cloudflare Worker route exposure,
  CloudFront signed-URL bypass, Bunny/KeyCDN origin-shield, edge TTL,
  origin-pull X-Forwarded-Host injection, CDN purge-API auth.
- **Wave H — Payment/PCI (#58-62):** Stripe/PayPal/Square detection,
  test-key leak in production HTML, PCI-DSS 4.0 checklist, PCI evidence
  JSON pack, 3DS2 hint, WooCommerce order-IDOR.
- **Wave I — Compliance frameworks (#63-67):** HITRUST CSF v11.4, CMMC 2.0,
  NIST CSF 2.0, CIS Critical Controls v8, ISO 27001:2022 Annex A — 106-check
  mapping in `compliance_v2.json`.
- **Wave J — AI/ML output safety (#68-72):** hallucination-verification re-prompt,
  per-backend cost tracking, llama.cpp local backend, prompt-injection
  guard, private-data masking (email/IP/card/SSN/AWS-key/Stripe-key/PAT).
- **Wave K — UX maturity (#73-82):** built-in locales beyond en/es (FR, DE,
  PT-BR, JA, ZH-CN), GUI a11y audit, vim keys, power shortcuts, OS dark-mode
  follow, sound packs, quiet hours, star/favourite, saved searches,
  Obsidian + Notion export.
- **Wave L — Plugin-dev outreach (#83-86):** coordinated-disclosure email,
  wp.org submission, Patchstack vendor, CVE 5.1 record builder.
- **Wave M — Headless/API-first WP (#87-91):** WPGraphQL introspection +
  alias-amplification, Next.js/Gatsby decoupled, Bedrock layout,
  Atlas/WPE purge-token leak, REST permalink rewrite.
- **Wave N — Reliability (#92-94):** per-check perf regression,
  per-target scan-time alerts, cache-hit-rate trend (30 days).
- **Wave O — Browser replay (#95-97):** Playwright attacker-session
  recorder (trace.zip), visual diff between scans, attacker-view MP4
  via ffmpeg.
- **Wave P — Hardware keys (#98-100):** WebAuthn for API server (fido2),
  Yubikey GPG encryption, TPM-backed secret storage (tpm2-tools / DPAPI).
- **Wave Q — WAF tuning (#101-104):** scanner allow-list generator,
  Cloudflare API push, ModSecurity CRS export, log-only mode flip.
- **Wave R — Genuinely novel (#105-109, 111, 112):** AI false-positive
  learner (per-finding confidence penalty), honeypot fingerprint detector,
  mutation testing of WPSecScan's own checks, visual regression of HTML
  reports, X25519 encrypted scan-result sharing, remediation A/B test
  store, hash-chained Merkle log.

Skipped from brainstorm: #110 audio briefing TTS (user opt-out).

**Bug fixes during QA:**
- `wp_membership_lms_audit` dead `_probe()`/`ctx_url()` placeholder removed
- `hardware_keys` PGP recipient regex tightened (rejects malformed emails)
- `osint.py` + `upload_path_predictable.py` datetime.utcnow() → tz-aware
- `plugin_outreach` datetime.utcnow() → tz-aware

---

## Round-58 — 117-feature mega-round (best WordPress security scanner)

A sweeping round across 14 categories (P-CC). Inventory: **120 → 136 checks**.
Tests: **392 → 427 passing**. See CHANGELOG.md for the full list. Headlines:

- 16 new WordPress / cloud / exploit-primitive checks (waves P-R)
- OSINT enrichment (ASN, geo, bug-bounty, cert-tx) — wave S
- Compliance: HIPAA / FERPA / SOC 2 / FedRAMP / GDPR mappings, risk-aging,
  bug-bounty submission templates, trust-center page generator — wave T
- Continuous mode, CIDR-discovery (capped /24), per-site profiles,
  scan-windowing — wave U
- Executive pack: $-cost-of-remediation + breach-exposure estimates,
  industry benchmark, priority queue, 4 stakeholder variants — wave V
- AI / LLM assist (OpenAI / Anthropic / Ollama — BYO key, `WPSECSCAN_NO_AI=1`
  hard-disable, data warnings in docstrings) — wave W
- VS Code extension scaffold + pre-commit hook + cross-platform build
  recipes (Mac .app, Linux .deb/.rpm, Homebrew/Scoop/winget) — wave X
- BloomFilter, worker-pool, per-check memoization — wave Y
- CyberChef/Shodan link builders, system tray, desktop notifications
  (shell-escaped), 6 color themes, achievements, custom-CSS reports — wave Z
- Self-health, --profile cProfile, watchdog, live-tail, retry policy — wave AA
- gpg encrypt-at-rest, symlink-safe shred, sandboxed plugin subprocess,
  Sigstore wrapper, permissions audit — wave BB
- Built-in WP-security tutorial (8 steps), CTF practice mode, plain-English
  explainer per check — wave CC

### Round-58 QA pass (7 issues fixed before push)
- `shred_older_than` symlink guard, CIDR /24 hard cap, `desktop_notify`
  XML/AppleScript escape, `bounty_format` str.format injection guard,
  OSINT 24h bounty cache + pacing, `WPSECSCAN_NO_AI` env, data warnings
  on AI docstrings.

---

## Round-57 — competitor-parity (wpscan / nuclei / OWASP ZAP / turbo-intruder)

A 40-feature parity round that brings WPSecScan close to feature-coverage of
the established big-name security tools. Inventory grew from **104 → 120 checks**.
Tests: **392 pass** (was 358).

### Wave A — wpscan parity (8 items)
| ID | What |
|---|---|
| `timthumb` | Probes 8 timthumb.php paths + parses version banner; flags `<=2.8.13` as CVE-2011-4106/4663 RCE |
| `plugin_hash_fingerprint` | Hashes plugin static assets and matches against a shipped version map — works even when readme.txt is stripped |
| `users_deep` | 10-source username enumeration: oEmbed, RSS, comments feed, WP-core + Yoast author sitemaps, post HTML |
| `plugin_archive_fuzz` | For every detected plugin slug, probes `slug.{zip,tar,gz,rar,7z,sql.gz,bak,old}` — backup-source leak detection |
| `premium_license_leak` | Scans HTML/JS for leaked Elementor Pro / WP Rocket / Gravity Forms / WPMU DEV license keys |
| `xmlrpc_method_brute` | Brute-forces ~30 hidden XML-RPC method names (Jetpack, WC, plugin-internal) — finds methods that `system.listMethods` hides |
| `ua_rotation` | 20 realistic User-Agent pool with per-request rotation — bypasses naive UA-based bot blockers |
| `rate_limit` | External-API rate-limit awareness (X-RateLimit-* / Retry-After) for KEV/EPSS/VT/GH/HIBP/AbuseIPDB integrations |

### Wave B — nuclei parity (9 items)
| ID | What |
|---|---|
| `yaml_templates` | nuclei-style YAML template engine (subset) — drop `.yaml` in `~/.wpsecscan/templates/`, runs against target |
| DSL matchers | `status` / `word` / `regex` / `size` matchers with `condition: and\|or` |
| `yaml_workflows` | Workflow chaining — entry template's match gates execution of subsequent templates filtered by tag/id |
| `interactsh` shim | Out-of-band callback registration via the public `oast.live` Interactsh; SSRF-safe (refuses loopback/RFC1918) |
| `dns_templates` | DNS-block templates (A/AAAA/MX/TXT/NS/CNAME) — minimal manual resolver, no dnspython dep |
| `headless_templates` | Playwright-driven templates with `navigate` / `wait` / `screenshot` actions + post-JS DOM matchers (aggressive) |
| `auto_scan` | Tech-fingerprint-driven template auto-selection — runs only WP-tagged templates against detected WP sites |
| `template_fuzz` | Per-template payload substitution — `{{payload}}` × N values × every URL param |
| `template_signature` | SHA256 manifest + optional GPG signature verification for community-template tamper detection |

### Wave C — OWASP ZAP parity (12 items)
| ID | What |
|---|---|
| `spider_crawl` | BFS recursive same-origin crawler bounded by max_depth=3, max_pages=200, respects robots.txt |
| `scan_modes` | Named active/passive/authenticated/full modes — concurrency auto-tunes per mode |
| `session_context` | Saved login flows per target — auto-re-auth on mid-scan session timeout, env-var creds |
| `forced_browse` | DirBuster-style hidden-path discovery from a 200-entry curated wordlist (extendable via `~/.wpsecscan/extra_paths.txt`) |
| `marketplace` upgrade | Static catalogue now merged with a 24h-cached remote catalogue (drop URLs in `WPSECSCAN_MARKETPLACE_URL`) |
| `websocket_fuzz` | Auto-discovers WS endpoints from HTML, sends oversized/malformed/XSS/SQL-meta frames (aggressive) |
| `HUD.md` | Heads-Up Display documented as intentionally not-implemented (WebExtension complexity); alternatives listed |
| `openapi_scanner` | Auto-discovers OpenAPI/Swagger spec at common paths, probes every documented endpoint for unauth access |
| `alert_filters` | `~/.wpsecscan/alert_filters.json` — hide / downgrade known findings (accepted risks) post-scan |
| `js_plugin` | JS-scriptable checks via Node subprocess — drop `.js` files in `~/.wpsecscan/plugins/`, 10MB stdout cap |

### Wave D — PortSwigger turbo-intruder parity (6 items)
| ID | What |
|---|---|
| `turbo_engine.burst` | HTTP/2-multiplexing high-RPS burst (default 200 concurrent) |
| `turbo_engine.last_byte_sync` | Open N TCP sockets, send everything-except-CRLF, fire final byte simultaneously — race-condition ~microsecond sync |
| `turbo_engine.single_packet_h2` | Coalesce N HTTP/2 HEADERS frames into one TCP packet |
| `attack_scripts` | Drop a Python script in `~/.wpsecscan/attacks/`, run with `--attack <id> <target>`, gets `engine` + `Finding` |
| `response_diff` | Statistical outlier detection across N response summaries (status / length-σ / body-hash) |
| `attack_checkpoint` | `CheckpointedRunner` — pause/resume long fuzz runs, persists every 50 completions |

### Wave E — cross-cutting (5 items)
| ID | What |
|---|---|
| `burp_import` | Read Burp Suite `.burp` SQLite projects → HAR format → replay via existing har_replay |
| `pcap_replay` | Read `.pcap` / `.pcapng` (scapy optional dep) → HAR → replay |
| `mobile_app_endpoints` | Discovers app association files (`apple-app-site-association`, `assetlinks.json`) — surfaces mobile-app endpoint shapes |
| `intel_freshness` | Per-source "last updated" scoreboard — flags KEV/EPSS/Wordfence/Sucuri caches that are >30 days stale |
| `host_recon` | TCP probe to common service ports (Redis, Mongo, Docker, k8s API, etc.) on the WP-host IP |

### UX additions
- **GUI update notice**: pops up at launch when a newer release exists, with a Download button that opens the GitHub release page. Help → Check for updates now to force a re-check.
- **Activity bus emits** for the spider + YAML template engine so the live dashboard shows them firing.

### QA bugs fixed in this round
Internal QA audit found 13 issues; the 4 critical + 4 high-priority were patched before push:
- `template_engine.py` NameError on `re.error` alias
- `headless_templates.py` missing aggressive-mode gate
- `rate_limit.py` unbounded state dict (now LRU-capped at 64 services)
- `turbo_engine.py` socket leak on connect-failure path
- `interactsh.py` SSRF-safe server validation (refuses loopback/metadata/RFC1918)
- `js_plugin.py` 10 MB stdout cap
- `template_signature.py` gpg stderr sanitisation

---

## Round-56 — "See it all working" visibility upgrade

Three rounds of feature additions had left most of the work invisible: KEV
fetches, EPSS scoring, Playwright screenshots, audit shipping, OTel spans,
incremental skips — all silent. Round-56 surfaces them.

- **Activity event bus** (`wpsecscan/activity.py`) — every feature emits a
  short categorised event (threat-intel / reporter / integration / governance /
  meta / artifact). 25 emit sites wired across check-health, incremental, KEV,
  EPSS, VirusTotal, Sucuri, CVE-explainer, audit-log, audit-shipping,
  screenshot capture, auto-update, and every reporter.
- **Live multi-panel console dashboard** during scans
  (`wpsecscan/console_live.py`) — `rich.Live` layout with a header (target +
  elapsed + check counter), a streaming severity-coloured findings panel,
  an activity-feed panel with category badges, and a progress-bar footer
  with ETA + current-check label. Falls back to the static console reporter
  when stdout isn't a TTY or `--no-live` is set.
- **End-of-scan "What ran" panel** — appended to the console reporter; lists
  inventory totals (selected / ran / skipped / auto-disabled), per-category
  event counts, and any slow-check budget warnings.
- **GUI activity tab** — the right-side detail pane is now a `ttk.Notebook`
  with two tabs: "Finding detail" (unchanged) and "Activity" (new). The
  Activity tab subscribes to the bus through the existing 40 ms drain queue
  and auto-scrolls with category-coloured badges.
- **`--demo` flag** + Tools → Demo mode — synthetic scan with ~30 findings
  across every severity/OWASP slot and ~25 activity events at ~80 ms
  intervals so every category badge appears. Writes every reporter's
  artifact (HTML / JSON / MD / XLSX / SARIF / Burp / exec-pdf / attestation /
  SBOM / auto-PR script) to `~/.wpsecscan/demo/` for screenshot / training use.
- **JSON reports now embed `activity_log`** — the saved JSON contains the
  full timeline from the bus, so a replayed report in the two-report diff
  viewer can show what fired during the original scan.

Tests: **358 pass** (was 340).

---

## Round-55 (H-O) — what landed

The 47-item round-55 expansion brought the inventory from 94 to **104 checks**
plus a deep set of non-check modules (api server, sbom, attestation PDF,
auto-PR, GraphQL-style query, OTel traces, RBAC, audit-log shipping, chat
bots, region egress, hot-reload, plugin scaffold, color-blind palette).

### New active checks (Wave A)
| ID | What it does |
|---|---|
| `cloud_metadata_ssrf` | Escalates a confirmed SSRF candidate to AWS / GCP / Azure / DO / Hetzner / Alibaba / Oracle / K8s / Docker metadata endpoints |
| `dns_rebinding` | Uses public `rbndr.us` rebinder to compare two consecutive fetches; mismatch flags rebinding-class SSRF |
| `hpp` | HTTP Parameter Pollution — duplicate `?id=` with evil value, compare to baseline |
| `header_smuggling_case` | Case-variant + duplicated headers (Content-Length, Transfer-Encoding) — proxy/backend disagreement = smuggling precondition |

### New passive checks (Wave A)
| ID | What it does |
|---|---|
| `http3_fingerprint` | Reads `Alt-Svc: h3="..."` + server header to identify the QUIC implementation |
| `session_fixation` | Pre-plants cookies, hits `/wp-login.php`, flags if server doesn't regenerate them |
| `csrf_entropy` | Samples 12 nonces, computes Shannon entropy + repetition rate |
| `backup_file_fuzz` | ~30 less-common variants (wp-config.php~, .swp, .tmp, .orig, IDE configs, editor leftovers) |
| `hostname_collision` | Compares apex vs www variant — different content flags a takeover-class risk |
| `plugin_route_fuzz` | For every detected plugin, probes known unauth REST endpoints (15 plugins covered) |

### Reporting / UX (Wave B)
- **Per-finding screenshot capture** (`wpsecscan/screenshot.py`) — Playwright captures critical/high findings, embeds base64 PNGs (optional dep)
- **Reference link database** (`wpsecscan/data/references.json` + `references.py`) — per-check_id OWASP / PortSwigger / HackTricks / YouTube links
- **Native Jira / Linear / GitHub Issues export** (`reporters/issue_export.py`) — emits curl scripts; user reviews + executes
- **User-tunable severity weights** (`wpsecscan/risk_weights.py`) — overrides via `~/.wpsecscan/risk_weights.json`
- **Compliance gap matrix** (`wpsecscan/compliance_gap.py`) — per-framework "uncovered key controls" report
- **Light / dark / auto theme** + **color-blind-safe palette** in HTML report — toggles top-right, persisted in localStorage

### Reliability (Wave C)
- **Auto-update channel** (`wpsecscan/auto_update.py`) — daily GitHub-releases check, opt-out via `--no-update-check`
- **Self-healing + per-check budget tracker** (`wpsecscan/check_health.py`) — auto-disable check after 3 failures; flag 5×-over-median duration
- **Crash auto-submit helper** (`wpsecscan/crash_submit.py`) — redact secrets, build pre-filled GitHub Issue URL
- **SBOM emission** (`wpsecscan/sbom.py`) — `wpsecscan --sbom out.json` writes CycloneDX 1.5
- **Code-signing docs** (`CODE-SIGNING.md`) — EV cert procurement + CI integration

### Perf (Wave D)
- **HTTP/2 multiplexing** — already wired (`http2=True` in `wpsecscan/http.py`)
- **Incremental scan** (`wpsecscan/incremental.py`) — `--since YYYY-MM-DD` skips low-churn checks for targets whose snapshot is newer
- **Per-host learned baseline** (`wpsecscan/incremental.py`) — anomaly detection across rescans
- **Redis-backed CVE DB share** (`wpsecscan/redis_cache.py`) — opt-in via `WPSECSCAN_REDIS_URL`

### Extension points (Wave E)
- **Custom-check scaffold generator** (`wpsecscan/plugin_scaffold.py`) — drops a worked-example `.py` into `~/.wpsecscan/plugins/`
- **GraphQL-style report query** (`wpsecscan/report_query.py`) — `--query 'severity in [critical,high], check_id startswith ssrf'`
- **OpenTelemetry traces** (`wpsecscan/otel.py`) — opt-in via `WPSECSCAN_OTLP_ENDPOINT`; one span per check
- **Versioned report JSON schema** (`wpsecscan/data/report.schema.json`)
- **Hot-reload checks** (`wpsecscan/hot_reload.py`) — `reload_custom_checks()` without restarting the GUI

### Team / collab (Wave F)
- **Embedded HTTP API server** (`wpsecscan/api_server.py`) — `--api-server 127.0.0.1:8765 --api-token <secret>`; stdlib-only, 5 endpoints incl. `/openapi.json`
- **Org dashboard** (`reporters/org_dashboard.py`) — per-business-unit risk rollup
- **RBAC** (`wpsecscan/rbac.py`) — reader / scanner / admin roles; bcrypt-hashed tokens; sha256 fallback
- **Audit-log shipping** (`wpsecscan/audit_log_ship.py`) — Splunk HEC / Datadog / Loki
- **Slack + Discord chat bots** (`wpsecscan/chat_bot.py`) — translation layer; wire into the API server's route

### Compliance / governance (Wave G)
- **Per-region egress** (`wpsecscan/region_egress.py`) — `--region eu-west-1` resolved via `WPSECSCAN_PROXY_EU_WEST_1` env
- **Customer-facing attestation PDF** (`reporters/attestation.py`) — one-page deliverable; reportlab or HTML fallback
- **Auto-PR with fix** (`wpsecscan/auto_pr.py`) — `--auto-pr --auto-pr-repo owner/name` writes a `gh pr create` shell script

### Polish (Wave H)
- **Per-finding fix feedback** (`wpsecscan/fix_feedback.py`) — "did the fix work?" yes/no per finding
- **Trend markdown export** (`wpsecscan/trend_md.py`) — unicode-spark + table for any URL
- **Shell completion** (`wpsecscan/completion.py`) — `--completion bash|zsh|powershell`
- **i18n wired into GUI** — Language submenu under View; English + Spanish; user files in `~/.wpsecscan/locales/`
- **Onboarding wizard** (`gui_windows.open_onboarding_wizard`) — first-run token setup for HIBP / Wordfence / Patchstack / VT / AbuseIPDB / GitHub
- **Color-blind-safe palette** — `data-palette=cb` attribute, deuteranopia-friendly hues

### New CLI flags (round-55)
| Flag | Purpose |
|---|---|
| `--api-server HOST:PORT` | Run the embedded HTTP API server instead of a scan |
| `--api-token TOKEN` | Bearer auth for the API server (or set `WPSECSCAN_API_TOKEN`) |
| `--region NAME` | Compliance-aware egress proxy |
| `--sbom OUT.json` | Write a CycloneDX 1.5 SBOM and exit |
| `--attestation OUT.pdf` | Write a customer-facing attestation PDF after the scan |
| `--attestation-vendor NAME` / `--attestation-customer NAME` | Header fields for the attestation |
| `--auto-pr` + `--auto-pr-repo owner/name` | Write a `gh pr create` script of suggested fixes |
| `--query EXPR` | GraphQL-style filter against the report |
| `--since YYYY-MM-DD` | Incremental mode (skip low-churn checks for fresh targets) |
| `--completion bash|zsh|powershell` | Print a completion script and exit |
| `--no-update-check` | Skip the GitHub-releases update probe at startup |

### Tests
342 pass (was 281 after round-54). `tests/test_round_55.py` adds 36 new tests
covering every wave A-H module plus inventory/tag/compliance wiring checks.

---

## Round-54 (A1-G4) — what landed

The 54-item A1-G4 round expanded WPSecScan from 80 → 94 checks and added the
following non-check capabilities:

**New active checks (Wave 2 + 5 + 9):** `ssti`, `nosql_injection`,
`path_bypass`, `race_condition`, `dom_xss_headless` (optional Playwright).

**New passive / threat-intel checks:** `webdav`, `dev_params`,
`abuseipdb_lookup`, `waf_ruleset`, `oauth_oidc`, `saml_xsw`,
`s3_bucket_discovery`, `github_leak_search` (opt-in), `jwt_audit`.

**Threat-intel integrations:** CISA KEV catalog (`integrations/cisa_kev.py`),
EPSS scoring (`integrations/epss.py`), VirusTotal URL/IP
(`integrations/virustotal.py`), Sucuri SiteCheck
(`integrations/sucuri_sitecheck.py`), Wordfence/NVD CVE explainer
(`cve_explainer.py`).

**Per-check tag schema** now includes `cwe` (e.g. `CWE-79`) and `d3fend`
(e.g. `D3-IVA`) fields in `data/check_tags.json` (C4 + C9).

**New CLI flags:**
- `--fail-on critical|high|medium` — override exit-code logic (D5)
- `--abuseipdb-token`, `--vt-token`, `--github-search-token` (C6 / C5 / B6)
- `--diff-against BASELINE.json` — emit only the NEW / RESOLVED deltas (D4)
- `--shell` — drop into a Python REPL with the report pre-bound (F1)
- `--burp-export` — write Burp Suite scope XML (D7)
- `--exec-pdf` — write a one-page executive summary PDF (E1, reportlab or HTML fallback)
- `--replay-har HAR_FILE` — re-execute a recorded HAR against the target (F2)
- `--daemon CONFIG.yml` — cron-style scheduled scans (D6)

**Reporters added:**
- `reporters/exec_pdf.py` — one-page non-technical summary (E1)
- `reporters/diff_viewer.py` — standalone two-report drag-and-drop HTML viewer (E4)
- `reporters/burp_export.py` — Burp Suite project XML (D7)
- HTML report now embeds an inline severity × OWASP-category SVG heatmap (E2)

**GUI windows added:**
- Drop-in marketplace browser (F5)
- E3 interactive playbook walker (per-finding right-click → step-by-step tool sequence)
- E7 drill historical findings by OWASP/ATT&CK/CWE/D3FEND tag
- E8 multi-URL trend overlay with line chart
- E10 5-step guided tutorial (auto-shows on first launch)
- G1 assign-owner + G2 comment-thread right-click actions per finding

**Infrastructure / docs:**
- GitHub Actions workflow (`.github/workflows/wpsecscan.yml`) for nightly + PR scans (D1)
- GitLab CI / Jenkins / Azure DevOps templates (`ci/`) (D2)
- `Dockerfile` + `docker-compose.yml` (D3)
- `SDK.md` — embeddable importable API surface (F6)
- `DISTRIBUTED-SCAN.md` — patterns for sharding multi-target scans (G4)
- `wpsecscan/audit_log.py` — append-only JSONL who-ran-what-when (G3)
- `wpsecscan/i18n.py` — translation dict, English + Spanish (E6)
- `wpsecscan/har_replay.py` — fidelity HAR-replay engine (F2)
- Custom signature drop-in via `~/.wpsecscan/signatures/*.json` (F3)
- Custom payload drop-in via `~/.wpsecscan/payloads/*.json` (F4)

**Tests:** 281 pass (was 260) — `tests/test_round_54.py` adds happy-path
tests per new module plus inventory + tag/compliance wiring verification.

---

## 1. Checks (94 total)

Each check returns zero or more **findings**. Every finding carries a `severity` (info / low / medium / high / critical), a **confidence** indicator (low / medium / high), a per-check **OWASP Top 10** tag, a **MITRE ATT&CK** technique ID, and a per-check **PCI-DSS / NIST 800-53 / ISO 27001** compliance mapping.

### Recon (always on)

| ID | What it does |
|---|---|
| `waf` | Detects WAF / CDN (Cloudflare, Sucuri, Wordfence, Akamai, AWS WAF, …) and stashes the result for downstream checks |
| `core_version` | WordPress core version via meta-generator, /readme.html, /feed/ |
| `plugins` | Plugin slug + version enumeration from HTML, REST, and known asset paths |
| `themes` | Theme slug + version from /wp-content/themes/* and style.css |
| `users` | User enumeration via ?author=N, /wp-json/wp/v2/users, login-error timing |
| `subdomains` | Pulls crt.sh, hackertarget, and Wayback to discover sister domains |
| `dns_security` | SPF / DMARC / DKIM TXT-record audit |
| `favicon_fingerprint` | WordPress-version fingerprint via /wp-admin favicon hash |
| `favicon_hash` | **NEW** · Computes the Shodan-style MMH3 favicon hash and gives you a search URL to find sister sites |
| `http2_settings` | **NEW** · HTTP/2 negotiation + EOL Apache/nginx/IIS/LiteSpeed/OpenResty backend detection |
| `security_txt` | RFC 9116 /.well-known/security.txt audit |

### Surface (always on)

| ID | What it does |
|---|---|
| `exposed_files` | 40+ exposed-path probes (.env, wp-config.php.bak, .git, dumps, debug.log, …) |
| `directory_listing` | Open directory indexes on /wp-content/, /wp-includes/, plugins, themes |
| `backup_exposure` | UpdraftPlus, BackupBuddy, ai1wm-backups, duplicator, BackWPup directories |
| `debug_leaks` | WP_DEBUG, debug.log readability, error-page traces |
| `error_pages` | Custom error-page fingerprinting (stack-trace leaks, software banners) |
| `robots_sitemap` | robots.txt + sitemap.xml audit + Disallow-line crawl |
| `core_tampering` | Webshell paths in /wp-content/uploads/, install.php reachability |
| `secret_leak` | API keys (sk_live_*, AKIA*, AIza*, ghp_*, xoxb-) in HTML/JS |
| `source_maps` | sourceMappingURL exposure — leaks full pre-minified JS source |
| `js_supply_chain` | External JS hosts without SRI hashes (polyfill.io / bootcdn-style risks) |
| `mixed_content` | HTTP-in-HTTPS asset audit |
| `upload_path_predictable` | **NEW** · Probes `/wp-content/uploads/YYYY/MM/<common-name>` for guessable "private" admin uploads |

### Auth surface (always on)

| ID | What it does |
|---|---|
| `login` | wp-login.php + xmlrpc.php + system.multicall amplifier |
| `login_throttle` | 6-attempt synthetic-user wrong-password test (~12s) |
| `login_throttle_deep` | Configurable 10–500 wrong-login mapping with custom pacing (opt-in via `--deep-throttle`) |
| `admin_ajax_brute_surface` | admin-ajax.php throttle probe |
| `cookies` | Secure / HttpOnly / SameSite / Domain scoping for WP cookies |
| `app_passwords` | WordPress 5.6+ Application Passwords audit |
| `csrf_nonce` | _wpnonce presence on admin forms; admin-ajax `check_ajax_referer` audit |
| `oauth_redirect` | **NEW** · Unrestricted `?redirect_to=` / `redirect_uri=` on wp-login + 3 common OAuth-plugin endpoints |
| `nonce_freshness` | Nonce expiry / replay window audit |

### Transport / headers (always on)

| ID | What it does |
|---|---|
| `tls_headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server tokens |
| `tls_deep` | TLS version, cert expiry, cipher list |
| `tls_protocol_audit` | **NEW** · Tests acceptance of TLS 1.0/1.1, weak ciphers (RC4/3DES/NULL/EXPORT), cert expiry distance |
| `csp` | Deep CSP analysis — unsafe-inline, missing default-src, wildcard hosts |
| `cache_headers` | Cache-Control / Vary / private-content cacheability |
| `redirect_chain` | Redirect-loop + protocol-downgrade chains |
| `server_timing` | Server-Timing / X-Request-ID / X-Trace-ID / X-Debug-Token leaks |
| `http_methods` | TRACE / PUT / DELETE / OPTIONS enumeration |
| `cors` | Access-Control-Allow-Origin echo + Allow-Credentials misconfig |
| `cache_poisoning` | **NEW** · X-Forwarded-Host / X-Original-URL / X-Rewrite-URL reflection + cacheability check |
| `smuggling_probe` | **NEW** · Passive HTTP request-smuggling indicators (duplicate CL/TE, h2-to-h1 topology, chunked-on-HEAD) |

### APIs (always on)

| ID | What it does |
|---|---|
| `rest_api` | WP REST namespace map + /wp-json/wp/v2/users + /settings leaks |
| `wp_rest_methods` | OPTIONS enum on REST namespaces — flags unauth POST/PUT/DELETE |
| `ajax_surface` | Admin-ajax nopriv action enumeration |
| `wpgraphql` | WPGraphQL introspection + namespace audit |
| `graphql_dos` | **NEW** · Query-aliasing amplification probe (50× same field in one request) |
| `xmlrpc_deep` | XML-RPC method enum + system.multicall + pingback.ping SSRF check |
| `webhooks` | Plugin webhook endpoint discovery |
| `js_libraries` | jQuery/Bootstrap/Vue/React version detection with retire.js-style CVE refs |
| `websocket_audit` | **NEW** · WS/WSS upgrade probe + Origin enforcement check (CSWSH detection) |
| `woocommerce_audit` | **NEW** · WC REST /wc/v3/ namespace leak, OPTIONS write-methods, legacy ?wc-api=, sub-plugin inventory |

### Compliance / policy (always on)

| ID | What it does |
|---|---|
| `gdpr_dsr` | **NEW** · Probes /privacy/ and equivalents for a Data-Subject-Request process (GDPR Art. 12-15) |
| `cookie_consent` | **NEW** · Detects non-essential cookies set on first page load with no consent banner present |
| `a11y_lite` | **NEW** · Smoke check for &lt;html lang=&gt;, alt= on images, &lt;title&gt; presence |

### CVE matching (always on, DB-backed)

| ID | What it does |
|---|---|
| `core_cves` | Matches WP core version against Wordfence Intelligence DB |
| `plugin_cves` | Matches plugin versions + runs **307 confirmed exploit signatures** (when aggressive) including wp-cron, phpMyAdmin, install.php, adminer, polyfill.io supply-chain, etc. |
| `theme_cves` | Theme version matching + theme-CVE signatures (Bricks, Divi, Avada, …) |
| `hibp` | HaveIBeenPwned breach lookup for discovered usernames + emails |

### Hosting-specific

| ID | What it does |
|---|---|
| `wp_engine_misconfig` | **NEW** · WP Engine-specific probes (/_wpeprivate/, wpe_common.php, mu-plugins leaks) |
| `multisite` | WP Multisite-specific surface (wp-signup.php, blog-list.json) |

### Active probes (`--aggressive` only)

| ID | What it does |
|---|---|
| `sqli` | SQL injection probes — error-based, time-based, UNION |
| `xss_reflected` | Reflected XSS payload testing |
| `open_redirect` | Open-redirect probes against query-param redirects |
| `ssrf` | SSRF probes (AWS/GCP/Azure/DO/Hetzner/Alibaba metadata + internal IPs) |
| `path_traversal` | LFI / path-traversal via ../, %2F, double-encode bypasses |
| `file_upload` | Upload-endpoint probes (READ-ONLY: sends no actual file content) |
| `default_creds` | admin/admin, admin/password, admin/wordpress, admin/changeme (max 10 attempts) |
| `core_tampering` | Active webshell probes + install.php seizure check |
| `sendmail_injection` | CRLF email-header injection probe |
| `prototype_pollution` | **NEW** · `?__proto__[x]=` and `?constructor[prototype][x]=` reflection test |
| `graphql_field_dos` | **NEW** · Depth-15 nested introspection query — tests if depth-limit middleware is enforced |
| `csv_export_csp` | **NEW** · Fetches common CSV-export endpoints and looks for `=` / `+` / `-` / `@`-prefixed cells (Excel formula-injection) |
| `waf_bypass_probe` | **NEW** · After WAF is detected, sends known-evil-looking payloads to test if the WAF actually filters or just fingerprints |

### Authenticated (when `--auth-user`/`--auth-pass` are set)

| ID | What it does |
|---|---|
| `authenticated` | Logs in, audits user roles, plugin list (incl. inactive), Site Health critical issues, dangerous options (default_role, can_compose_setup) |

---

## 2. CLI flags

```
USAGE: wpsecscan.exe [URL] [options]

Targets:
  URL                          A single site (https://example.com)
  --file FILE                  Newline-separated list of URLs

Output:
  --out PATH                   Output directory or filename stem (default: cwd)
  --json-only                  Suppress HTML
  --html-only                  Suppress JSON
  --csv                        Also write CSV (formula-injection neutralised per OWASP)
  --sarif                      Also write SARIF 2.1.0
  --no-console                 Suppress the colored console table
  --no-color                   Force plain text (or Rich is missing — auto-fallback)

Modes:
  --aggressive                 Enable active payload checks (14 of them)
  --prove                      For each confirmed aggressive finding, run a read-only proof
                               extractor. Requires --aggressive. Read-only.
  --deep-throttle              Run the deep login-throttle mapper
  --deep-throttle-attempts N   (10-500, default 120)
  --deep-throttle-pacing S     (5-60 seconds, default 10)
  --auth-user USER             Admin username for authenticated scan
  --auth-pass PASS             Admin password
  --ssh-audit user@host        Connect via SSH and run a read-only wp-cli audit
  --password-audit FILE        Offline: convert wp_users dump to a hashcat-ready file (no network)

Tuning:
  --timeout SECONDS            Per-request timeout (default 15)
  --concurrency N              Concurrent requests per host (default 10)
  --user-agent STRING          Custom User-Agent
  --insecure                   Don't verify TLS certs
  --wpscan-token TOKEN         WPScan API token (richer plugin CVE data)
  --hibp-token TOKEN           HaveIBeenPwned API key

Maintenance:
  --update-db                  Refresh the Wordfence vulnerability database
  --diff OLD.json NEW.json     Diff two saved JSON reports
  --debug                      Verbose internal logging
  --version
```

**Exit codes**: `0` = clean / info only · `1` = medium findings · `2` = critical or high findings · `130` = Ctrl+C.

---

## 3. Output formats

| Flag | File | What's in it |
|---|---|---|
| (default) | `<host>-<ts>.html` | Browser-ready report with risk banner (score + letter grade), color-coded exploit playbooks per finding, OWASP/ATT&CK/PCI/NIST/ISO chips, copy-to-clipboard buttons per command, "🖨 Print / Save as PDF" button |
| (default) | `<host>-<ts>.json` | Full report + per-finding `confidence`, per-check `tags` + `compliance`, top-level `risk_grade` letter, all enrichment HTML gets |
| `--csv` | `<host>-<ts>.csv` | Spreadsheet import. Cells starting with `=` / `+` / `-` / `@` / tab are prefixed with `'` per OWASP CSV-injection prevention |
| `--sarif` | `<host>-<ts>.sarif` | SARIF 2.1.0 for GitHub Code Scanning, Azure DevOps, etc. |

---

## 4. GUI features

### Toolbar (always visible)
- **URL** dropdown with last 20 scanned sites
- **Scan / Cancel / Re-scan / Diff w/ last / Open HTML / Open folder / Copy JSON** buttons (tooltips on disabled buttons explain when they activate)
- **Live ETA** label that recomputes as toggles change
- **Risk score badge** — large color-coded `0-100` with letter grade
- **Persistent toast** (bottom-right) for "✓ JSON copied", "✓ Markdown exported", etc.

### Filtering
- Per-severity show/hide (info is hidden by default since a typical scan emits ~50)
- Search box (live filter on title + evidence)
- **Filter pills**: Only NEW (vs last scan) · Only CONFIRMED · Hide annotated
- Sort by severity

### Per-finding right-click menu
- Copy URL · Copy curl-replay · Open URL in browser
- Copy finding as markdown
- **Annotations**: Mark as accepted risk / Mark as false positive (persisted per-URL)
- Run nuclei tag for this check
- Open in sqlmap (uses the proven param/URL)

### Per-finding detail pane
- Severity badge · confidence chip (HIGH/MED/LOW) · OWASP + ATT&CK chips
- Evidence (mono code block)
- Remediation
- **Exploit playbook** — concrete curl/sqlmap/Metasploit/nuclei/wpscan/ffuf commands with `{target}` substituted
- Right-click: Copy selection · Copy fix · Copy finding as markdown

### Tools menu
- **Payload Tester** (Ctrl+T) — send one curated payload at a time, save as finding
- **Multi-target scan** — paste/load a URL list, scan each, one-row-per-site dashboard with risk score + Δ-vs-last
- **Schedule recurring scan** — registers a Windows Task Scheduler job (`schtasks /Create /TN WPSecScan_<host>`)
- **Show risk trend for current URL** — ASCII sparkline of historical scores

### File menu
- **Profiles** — save / load named toggle presets (Quick, Deep, Audit, …)
- **Export all findings as Markdown…** — single .md file with headers, code-fenced evidence, remediation
- **Settings** (Ctrl+,) — deep-throttle attempts/pacing + webhook URL (Slack/Discord/Teams/PagerDuty) + threshold

### Help menu
- Keyboard shortcuts list
- About (non-modal — stays open during scans)

### First-run experience
- Empty detail pane shows a 5-step "Get started" panel with clickable links to Settings, Schedule, Trend, Payload Tester, and Keyboard shortcuts

### Keyboard shortcuts
- **F5** — Scan
- **Esc** — Cancel scan / close any side window
- **Ctrl+,** — Open Settings
- **Ctrl+T** — Open Payload Tester
- **Ctrl+L** — Focus URL field
- **Ctrl+E / Ctrl+W** — Expand / collapse tree
- **Ctrl+J** — Copy JSON
- **Ctrl+H** — Open last HTML report
- **Ctrl+↑ / Ctrl+↓** — Cycle through findings

---

## 5. Configuration files

Everything is stored in `~/.wpsecscan/` (override with `WPSECSCAN_HOME` env var):

| File | Purpose |
|---|---|
| `history.json` | Last 20 scanned URLs (for the URL dropdown) |
| `profiles.json` | Named scan profiles (toggles + deep-throttle settings + webhook config) |
| `annotations.json` | Per-finding annotations (accepted-risk / false-positive) |
| `reports/<host>.json` | Snapshot of the most-recent scan per URL (for diff + trend) |
| `wordfence.json` | Local cache of the Wordfence vulnerability DB |

---

## 6. Webhooks

POST to one of these allow-listed hosts when a scan finds anything ≥ chosen severity:

- `hooks.slack.com` (Slack incoming webhooks)
- `discord.com`, `discordapp.com`, `ptb.discord.com`, `canary.discord.com`
- `webhook.office.com` (Microsoft Teams)
- `events.pagerduty.com`

URL allow-list enforces: **HTTPS only, port 443 only, exact-host match, no raw IPs (incl. AWS metadata at 169.254.169.254)**. Failed webhook deliveries never block the GUI thread — they run in a background daemon thread with a 4-second timeout.

---

## 7. Compliance overlays

Every check is mapped to **PCI-DSS 4.0**, **NIST 800-53 Rev. 5**, and **ISO/IEC 27001:2022** controls. Shown as small color-coded chips in the HTML report (`PCI 6.2.4`, `NIST SI-10`, `ISO A.8.28`) and included in the JSON output.

---

## 8. Risk score + grade

The risk score is `0-100`, calculated from per-severity weights with per-tier caps:
- critical: −25 per finding (capped at −50)
- high: −10 (capped at −30)
- medium: −3 (capped at −12)
- low: −1 (capped at −8)
- info: 0

**Letter grade** for non-technical stakeholders:
- **A** 95+ · **B** 85-94 · **C** 70-84 · **D** 50-69 · **F** <50

Both shown in console, HTML, JSON, and GUI badge.

---

## 9. Confidence indicator

Each finding carries a **HIGH-CONFIDENCE** / **MED-CONFIDENCE** / **LOW-CONFIDENCE** chip separate from severity. Heuristic:
- Finding title starts with `[CONFIRMED]` (signature engine actively verified) → **HIGH**
- Prove-mechanism produced an `extra.proof` → **HIGH**
- `severity=critical` (default for any unconfirmed critical) → **HIGH**
- `severity=high` → **MEDIUM**
- `severity=low/info` → **LOW**
- WAF detected on this site → downgrade all unconfirmed findings by one tier

---

## 10. Safety / scope

**Permanent out-of-scope:**
- Online password brute-force (the deep-throttle probe uses a synthetic non-existent username with a single fixed wrong password — maps the defense, doesn't guess passwords)
- Auto-exploitation (the playbook *describes* commands; the user runs them)
- Write-side payloads in the library (load-time invariant + pytest scan enforce this)

**Defense-in-depth:**
- Webhook URLs validated against an allow-list (no raw IPs / non-443 ports / unrelated hosts)
- Scheduled-task URL validated by strict regex (no shell-meta injection in `schtasks /TR`)
- Payload Tester rejects file://, localhost, raw IPs, private/loopback addresses
- CSV exports neutralise formula-trigger characters
- Authenticated scans never log usernames in step callbacks
- Per-scan `RequestCache` is thread-safe; cleared on scan close

---

## 11. Test coverage

234 tests as of the last release:
- Per-check smoke + safety
- Engine: scanner, http cache, models, risk score, diff
- Reporters: console, HTML, JSON, CSV, SARIF
- Notifications: webhook URL validation (subdomain bypass, port injection, AWS metadata block)
- New modules: confidence, eta, tags, compliance, annotations, playbook
- Inventory: every check has a tag + compliance entry; every aggressive check self-skips without `--aggressive`
- Regressions: wp-cron / install.php / phpMyAdmin signatures must fire in aggressive mode

Run `pytest` to verify your build.

---

## 12. Inventory

| Category | Count |
|---|---|
| Checks | **80** (65 passive · 15 aggressive) |
| Payloads | **224** (SQLi / XSS / SSRF / LFI / open-redirect / header-injection) |
| Exploit signatures | **307** |
| Wordfence CVEs (offline DB) | ~7,000 |
| Optional CVE sources | Wordfence (always) · Patchstack (opt-in via `--patchstack-token`) · OSV.dev (auto, for JS libs) |
| Exploit-playbook entries | **39** |
| Tag entries | **80** (100% coverage) |
| Compliance entries | **80** (PCI-DSS + NIST + ISO, 100% coverage) |
| WAF rule templates | **10** (Cloudflare + ModSecurity + Nginx for top checks) |
| Recommendation engine entries | **17** |
| Tests | **251** |

## Round-Q feature additions (this release)

**Detection (4 new checks)**: `well_known` · `login_timing` · `sitemap_cve_probe` · `xxe_upload` (aggressive)
**Cross-cutting extensions**: CSS SRI added to `js_supply_chain`; active subdomain-takeover fingerprints (20 SaaS providers) extending `subdomains`; OSV.dev cross-reference in `js_libraries`; Patchstack DB merge in `db.update_db`.

**Engine**:
- Adaptive throttle — `http.py` Client auto-reduces concurrency on 429/503, restores after a clean streak. Visible via `client.throttle_stats()`.
- Smart-skip WAF — after 3 consecutive aggressive checks bounce off the WAF, the remaining aggressive checks are skipped with a summary.
- Resumable scans (`--checkpoint`) — checkpoint to `~/.wpsecscan/checkpoints/` after each check; on next run, offers to resume from the last completed check.
- Concurrent check groups (`--parallel-groups`) — non-aggressive checks within a group run concurrently; aggressive group stays sequential. ~30% faster on typical scans.

**UX**:
- Per-check disable grid (Tools → Enable/disable checks) — persisted to `~/.wpsecscan/disabled_checks.json`
- OWASP-grouped tree view (filter pill: "Group by OWASP")
- Search across all historical scans (Tools → Search scan history)
- Plugin-recommendation engine — Tools → Show fix recommendations; also rendered at the bottom of every HTML report
- Multi-target side-by-side compare — select 2+ rows in Multi-target window, click "Compare selected"
- Windows toast on critical finding mid-scan

**Outputs**:
- `--md` — Markdown report (handy for tickets / PRs / Slack)
- `--xlsx` — Excel workbook with per-OWASP-category sheets + Summary + All-findings, formula-injection-safe
- `--har FILE` — record every HTTP request/response to a HAR file (Authorization/Cookie headers redacted)
- WAF rule generator — each finding now ships with copy-pasteable Cloudflare + ModSecurity + Nginx snippets
- GitHub Issues auto-create (Settings → opt-in with repo + token) — one issue per finding ≥ threshold

**Extensibility**:
- Custom check loader — drop `*.py` files in `~/.wpsecscan/plugins/`; each file exposes `CHECK_ID`, `CHECK_NAME`, `IS_AGGRESSIVE`, `async def check(client, ctx)`. Auto-discovered at scanner startup.
