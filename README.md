# WPSecScan

[![tests](https://github.com/bryanflowers/wpsecscan/actions/workflows/tests.yml/badge.svg)](https://github.com/bryanflowers/wpsecscan/actions/workflows/tests.yml)
[![CVE feed](https://github.com/bryanflowers/wpsecscan/actions/workflows/cve-feed.yml/badge.svg)](https://github.com/bryanflowers/wpsecscan/actions/workflows/cve-feed.yml)
[![license](https://img.shields.io/github/license/bryanflowers/wpsecscan)](LICENSE)
[![release](https://img.shields.io/github/v/release/bryanflowers/wpsecscan)](https://github.com/bryanflowers/wpsecscan/releases/latest)
[![downloads](https://img.shields.io/github/downloads/bryanflowers/wpsecscan/total)](https://github.com/bryanflowers/wpsecscan/releases)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![checks](https://img.shields.io/badge/checks-226-brightgreen)](FEATURES.md)
[![CVE sources](https://img.shields.io/badge/CVE%20sources-8-blue)](docs/data-sources.md)
[![tests passing](https://img.shields.io/badge/tests-780%20passing-brightgreen)](tests/)
[![PyPI](https://img.shields.io/pypi/v/wpsecscan)](https://pypi.org/project/wpsecscan/)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-success)](docs/verify-release.md)
[![Sigstore signed](https://img.shields.io/badge/Sigstore-signed-blueviolet)](docs/verify-release.md)
[![threat-intel](https://img.shields.io/badge/threat--intel-10%20providers-orange)](FEATURES.md)

> **⚠ AUTHORIZED USE ONLY**
>
> WPSecScan is a defensive security tool. Use it **only** on sites you own
> or sites whose owner has given you **written permission** to test.
> Unauthorised scanning is illegal in most jurisdictions (e.g. the US
> Computer Fraud and Abuse Act, the UK Computer Misuse Act 1990, the EU
> Network and Information Security Directive). The maintainers accept no
> liability for misuse. By using this software you confirm you have the
> required authorisation for every target you scan.

**The most thoroughly-sourced WordPress vulnerability scanner — open source, AGPLv3, runs locally.**

226 checks across 18 categories. **8-source nightly CVE aggregator**
(NVD + GHSA + Mitre + OSV + Wordfence + WPVulnerability + CIRCL +
Patchstack). **SLSA L3 + Sigstore-signed releases**. **10-provider
threat-intel federation** (CISA KEV, EPSS, Exploit-DB, Metasploit,
ATT&CK Navigator, STIX, MISP, OpenCTI, OTX, GreyNoise). **Continuous
monitoring** (CT/DNS/WHOIS/RBL/honeypot/auto-rollback). **Active
exploit verification** with strict consent gating. **Enterprise
mode**: OIDC + SAML + RBAC + audit-log + approval workflow +
multi-tenant + quotas. **Distribution**: Docker, K8s, Homebrew, Snap,
Flatpak, winget, AUR, Chocolatey.

Original headline:
gives you a fresher and more complete vulnerability database than
any single paid or free service. Runs entirely on your machine — no
telemetry, no per-site licensing, no data leaves your box.

Ships as two standalone Windows binaries — no Python required on the machine you run them on.

- **`wpsecscan.exe`** — command-line scanner. Output: console + HTML + JSON + CSV + SARIF + Markdown + Excel (XLSX) + executive PDF + Burp scope XML + CycloneDX SBOM + shields.io status badge SVG.
- **`wpsecscan-gui.exe`** — full GUI with live progress tree, finding details, risk score,
  scan profiles, multi-target queue, scheduled scans, webhook alerts, exploit playbooks, and more.
- **`wpsecscan-companion.zip`** — WordPress plugin that exposes a read-only, token-gated
  REST endpoint so the scanner gets authoritative diagnostics in one round-trip (3× more
  accurate plugin/theme detection vs HTTP-probe guessing).

### Why people are switching to WPSecScan

- **8-source CVE aggregator** runs nightly on our infrastructure — pulls
  Wordfence + NVD + GitHub Security Advisories + Mitre CVE List + OSV.dev +
  WPVulnerability.com + CIRCL + Patchstack and merges them into one feed.
  Users get a strictly fresher + more complete DB than Wordfence/Patchstack
  alone. **6 of 8 sources are fully free, no key required.**
- **Daily DB refresh + per-CVE webhook alerts** — `wpsecscan schedule
  install` registers a daily 02:00 CVE-refresh + weekly 03:00 site scan
  on Windows Task Scheduler / macOS launchd / Linux systemd.
  `wpsecscan db subscribe https://hooks.slack.com/...` fires the moment a
  new CVE drops for a plugin you have installed.
- **15 compliance frameworks mapped** per check: OWASP Top 10 + MITRE
  ATT&CK + CWE + D3FEND + PCI-DSS 4.0 + NIST 800-53 + ISO 27001 + HIPAA +
  FERPA + SOC 2 + FedRAMP + GDPR + HITRUST CSF v11.4 + CMMC 2.0 +
  NIST CSF 2.0 + CIS Critical Controls v8 + ISO 27001:2022 Annex A.
- **11 report formats**: HTML, JSON, CSV, SARIF 2.1.0, Markdown, Excel
  (XLSX with per-OWASP-category sheets), executive PDF, CycloneDX SBOM,
  Burp Suite scope XML, attestation PDF, shields.io status-badge SVG.
- **10 third-party integrations** including Burp Suite project XML,
  OWASP ZAP findings import, Nuclei template auto-pull, JIRA / Linear /
  GitHub Issues bulk-create, Wordfence Cloud sync, Sucuri SiteCheck,
  Patchstack + WPScan write-back, WP Engine / Kinsta / WP.com host APIs.
- **AI-assisted remediation** with PII masking + prompt-injection guard +
  per-backend cost tracking. Bring your own OpenAI / Anthropic / Ollama /
  llama.cpp key. **`WPSECSCAN_NO_AI=1` to hard-disable.**
- **Privacy-first**: no telemetry, runs locally, supports SOCKS5/HTTP
  proxies (Tor friendly), `WPSECSCAN_NO_NETWORK=1` for air-gapped mode.

---

## Quick install

### Option A — `pip install wpsecscan` (any platform)

The simplest path on Linux, macOS, or Windows-with-Python:

```bash
pip install wpsecscan
wpsecscan --version
wpsecscan https://example.com --json-only
```

PyPI: <https://pypi.org/project/wpsecscan/>

For the optional GUI minimize-to-tray feature, install with the
`[ui]` extra (pulls in Pillow + pystray):

```bash
pip install "wpsecscan[ui]"
```

Other optional extras: `[pdf]` (reportlab for true PDF exec reports),
`[browser]` (playwright for headless DOM-XSS), `[yaml]` (pyyaml for
daemon config), `[ops]` (redis + bcrypt for enterprise mode), or
`[all]` to install everything.

### Option B — pre-built Windows binaries

1. Open `dist\` in this folder.
2. Copy `wpsecscan.exe` and `wpsecscan-gui.exe` somewhere on your PATH
   (e.g. `C:\Tools\` or `C:\Users\<you>\bin\`).
3. Done. No Python, no installer, no admin rights needed.

The first time you run them, Windows SmartScreen may warn that the publisher is unknown
(the binaries aren't code-signed). Click **More info → Run anyway**.

### Option C — build from source

Requires Python 3.10+ and PyInstaller. Open PowerShell in the project root:

```powershell
.\build.ps1
```

This creates a virtualenv in `.venv\`, installs dependencies from `requirements.txt`,
and runs PyInstaller. Output:

```
dist\wpsecscan.exe                  # CLI (~17 MB)
dist\wpsecscan-gui.exe       # GUI (~17 MB)
```

Both are single-file executables — copy them anywhere and they run on their own.

### Option D — run from source directly (development)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
python run.py https://example.com         # CLI
python run_gui.py                          # GUI
pytest                                     # 780 tests
```

---

## First scan

### GUI

1. Double-click `wpsecscan-gui.exe`.
2. Paste a URL into the URL field (e.g. `https://your-wp-site.com`).
3. Click **Scan**. Watch the live tree on the left and click any finding to read
   evidence, remediation, and the *Exploit Playbook* (concrete sqlmap/Metasploit/curl/nuclei commands).
4. When the scan finishes, the **Risk Score** badge at the top shows `0-100` color-coded
   (green/yellow/orange/red). HTML and JSON reports are saved to your user folder.

### CLI

```powershell
# Simple scan, HTML + JSON saved to current directory
wpsecscan.exe https://your-wp-site.com

# Custom output folder
wpsecscan.exe https://your-wp-site.com --out C:\scans\

# JSON only, no HTML
wpsecscan.exe https://your-wp-site.com --json-only --out C:\scans\

# Multiple targets from a file
wpsecscan.exe --file my-sites.txt --concurrency 5 --out C:\scans\

# Aggressive mode (active payload checks — SQLi, XSS, SSRF, etc.)
wpsecscan.exe https://your-wp-site.com --aggressive

# Authenticated scan
wpsecscan.exe https://your-wp-site.com --auth-user admin --auth-pass <pwd>

# Use a saved WPScan API token for richer plugin CVE lookups
wpsecscan.exe https://your-wp-site.com --wpscan-token <KEY>
```

**Exit codes**: `0` = clean / info only · `1` = medium findings · `2` = critical or high findings · `130` = Ctrl+C.

---

## What it checks (226 checks)

Passive checks always run; aggressive checks need `--aggressive`.

- **Recon**: WP core version · plugin enum (slug + version) · theme enum · user enum (`?author=`, REST `wp/v2/users`)
- **Surface**: 40+ exposed-path probes (`.env`, `wp-config.php.bak`, `.git/config`, debug.log, backup-plugin dumps, phpinfo, adminer, …) · WebDAV / OPTIONS enum · beta/test/debug query-parameter discovery
- **Auth surface**: `wp-login.php` + XML-RPC method enum + `system.multicall` amplifier check + rate-limit probe · OAuth2/OIDC discovery audit · SAML / XSW endpoint discovery · JWT audit (`alg=none` + weak HS256 brute-force)
- **Transport**: TLS version, cert expiry, HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, cookie flags
- **APIs**: REST namespace map, REST OPTIONS write-method enum, WPGraphQL introspection, CORS misconfig (full preflight matrix incl. `null` origin reflection)
- **Defensive posture**: WAF / CDN detection · WAF rule-set identification (CRS / AWS / Cloudflare Managed / Wordfence Premium) · DNS SPF / DMARC / DKIM · security.txt · AbuseIPDB reputation (opt-in)
- **Supply-chain**: external JS hosts + SRI hash check · source-map exposure · JS library version audit · S3 bucket discovery + public-ACL probe · GitHub leaked-token search (opt-in, scans your domain against AKIA/sk_live_/ghp_/etc.)
- **Subdomain attack surface**: certificate-transparency discovery · dangling-CDN takeover candidates · **cookie-tossing chain** detection (apex-cookie + takeover-able subdomain)
- **Server fingerprint**: Server-Timing, X-Request-ID, X-Debug-Token leaks
- **CVE matching**: 7000+ Wordfence CVEs + 307 high-confidence exploit signatures + 224 modern payloads · CISA KEV catalog enrichment · EPSS percentile scoring · VirusTotal URL/IP enrichment (opt-in)
- **Aggressive** (`--aggressive`): SQLi (error-based + time-blind escalator) · reflected XSS · SSRF · path traversal · open redirect · file upload · default credentials (max 10) · SSTI (7 template engines) · NoSQL operator injection · path-normalisation bypass (`..%2f`, `..;/`, …) · race-condition probe (parallel POSTs) · active HTTP smuggling (CL.TE / TE.CL) · headless DOM-XSS (Playwright, optional)
- **Deep** (`--deep-throttle`): 10-500 wrong-password attempts at 5-60s pacing to map your login throttle threshold (synthetic non-existent user, fixed wrong password — never brute-force)
- **Authenticated** (`--auth-user`/`--auth-pass`): logs in, audits user roles, plugins, Site Health, options

### Round-54 additions (Nov 2026 — A1-G4 catalogue)

WPSecScan grew from 80 → 94 checks plus a wide non-check toolkit:

| Area | New |
|------|-----|
| **Active probes** | `ssti`, `nosql_injection`, `path_bypass`, `race_condition`, `dom_xss_headless` (Playwright optional) |
| **Passive / intel checks** | `webdav`, `dev_params`, `abuseipdb_lookup` (`--abuseipdb-token`), `waf_ruleset`, `oauth_oidc`, `saml_xsw`, `s3_bucket_discovery`, `github_leak_search` (`--github-search-token`), `jwt_audit` |
| **Modified checks** | `subdomains` (B7 cookie-tossing chain), `cors` (B8 preflight matrix incl. `Origin: null`), `sqli` (A3 time-blind escalator), `smuggling_probe` (A6 active CL.TE/TE.CL) |
| **Threat-intel integrations** | CISA KEV, EPSS, VirusTotal, Sucuri SiteCheck, NVD/Wordfence CVE explainer |
| **Per-check tags** | new `cwe` (e.g. `CWE-79`) + `d3fend` (e.g. `D3-IVA`) fields in `data/check_tags.json` |
| **Reporters** | one-page executive PDF (`--exec-pdf`, uses reportlab or HTML fallback) · two-report drag-and-drop HTML diff viewer · Burp Suite scope XML (`--burp-export`) · severity × OWASP-category SVG heatmap embedded in HTML report |
| **CLI flags** | `--fail-on`, `--diff-against`, `--shell`, `--replay-har`, `--daemon`, `--abuseipdb-token`, `--vt-token`, `--github-search-token`, `--burp-export`, `--exec-pdf` |
| **GUI windows** | step-by-step exploit-playbook walker (right-click any finding) · drill historical findings by OWASP/ATT&CK/CWE/D3FEND tag · multi-URL risk-score trend overlay · drop-in marketplace browser · 5-step first-run tutorial |
| **Collab** | assign-owner + comment threads per finding (right-click) |
| **Infra / docs** | `.github/workflows/wpsecscan.yml` (nightly + PR scans) · GitLab CI / Jenkins / Azure DevOps templates in `ci/` · `Dockerfile` + `docker-compose.yml` · `SDK.md` · `DISTRIBUTED-SCAN.md` · audit-log JSONL of every scan invocation · custom signature / payload drop-in (`~/.wpsecscan/{signatures,payloads}/`) · i18n stub (en + es) |

---

## Output formats

Every scan produces:

| Flag                | File                     | Use case                                |
|---------------------|--------------------------|-----------------------------------------|
| (default)           | `<host>-<ts>.html`       | Open in a browser. Has copy-to-clipboard buttons for every command, color-coded exploit playbooks, and a "🖨 Print / Save as PDF" button in the top-right corner. |
| (default)           | `<host>-<ts>.json`       | Includes per-finding `confidence` (low/medium/high) and per-check `tags` (OWASP Top 10 + MITRE ATT&CK). For downstream tooling. |
| `--csv`             | `<host>-<ts>.csv`        | Spreadsheet import. Cells are escaped against Excel formula-injection. |
| `--sarif`           | `<host>-<ts>.sarif`      | GitHub Code Scanning, Azure DevOps, anything that ingests SARIF 2.1.0. |
| `--json-only`       | suppresses HTML          | CI / scripted use. |
| `--md`              | `<host>-<ts>.md`         | Markdown report for Confluence / GitHub / Slack threads. |
| `--xlsx`            | `<host>-<ts>.xlsx`       | Excel workbook with per-OWASP-category sheets. |
| `--har FILE.har`    | `FILE.har`               | HAR 1.2 recording of every HTTP request (Cookie/Authorization redacted). Replay with `--replay-har`. |
| `--burp-export`     | `<host>-<ts>-burp-scope.xml` | Burp Suite scope XML for hand-off to manual testing. |
| `--exec-pdf`        | `<host>-<ts>-exec.pdf`   | One-page non-technical executive summary. Uses `reportlab` if installed, else writes a print-friendly HTML file. |

### Round-54 CLI additions

| Flag                                  | Purpose                                                                                  |
|---------------------------------------|------------------------------------------------------------------------------------------|
| `--fail-on critical\|high\|medium`    | Override exit-code logic — non-zero only when a finding meets or exceeds the threshold.  |
| `--diff-against BASELINE.json`        | Compute the NEW / RESOLVED delta vs a saved JSON report, print to stdout.                |
| `--shell`                             | After scan, drop into a Python REPL with `report` pre-bound (for power users / IR).      |
| `--replay-har HAR_FILE`               | Re-run every request in a HAR file; optionally override the origin with `<target>`.      |
| `--daemon CONFIG.yml`                 | Cron-style scheduled scans driven by a YAML config (no Task Scheduler required).         |
| `--abuseipdb-token TOKEN`             | Enables the AbuseIPDB reputation check for the target's IP.                              |
| `--vt-token TOKEN`                    | Enables VirusTotal URL/IP enrichment.                                                    |
| `--github-search-token PAT`           | Enables GitHub code-search for the target's domain + common secret prefixes.             |

### Round-56 visibility flags

| Flag                                  | Purpose                                                                                  |
|---------------------------------------|------------------------------------------------------------------------------------------|
| `--demo`                              | Synthetic scan against a fake target — every check fires fake findings, every integration fires a fake activity event. Writes one of every artifact to `~/.wpsecscan/demo/`. Great for screenshots, smoke-testing an install, or training new users. |
| `--no-live`                           | Disable the live multi-panel rich dashboard during scans. The static console reporter still renders at the end. Useful for CI logs / piped output. |

---

## Power-user features (GUI)

- **Risk score**: 0–100, color-coded. Calculated from severity weights with per-tier caps.
- **Profiles** (File → Profiles): save the current toggle/pacing/threshold set as `"Quick"`, `"Deep"`, `"Audit"` etc. Loads with one click. Stored in `~/.wpsecscan/profiles.json`.
- **Recent URLs**: the URL field is a dropdown of the last 20 scanned sites.
- **Diff with last scan**: button appears after a scan if a previous JSON for the same URL exists in `~/.wpsecscan/reports/`. Shows `[NEW]` / `[RESOLVED]` per finding.
- **Multi-target scan** (Tools → Multi-target): paste/load a list of URLs, scan each in turn, one-row-per-site dashboard with risk score and Δ-vs-last-scan.
- **Scheduled recurring scan** (Tools → Schedule): registers a Windows Task Scheduler job (`WPSecScan_<host>`) that runs daily/weekly/monthly at a chosen time. Outputs to a folder you pick. Remove with `schtasks /Delete /TN WPSecScan_<host> /F`.
- **Risk-score trend** (Tools → Show risk trend): ASCII sparkline of historical scores for the current URL.
- **Webhook notify** (File → Settings → "Webhook notify"): one POST to Slack/Discord/Teams/PagerDuty when a scan finds ≥ chosen severity. Hosts validated against an allow-list — won't post to arbitrary URLs or raw IPs.
- **Finding annotations**: right-click any finding → "Accepted risk" / "False positive" with an optional note. Persisted per-URL in `~/.wpsecscan/annotations.json`.
- **Filter pills**: Only NEW (vs last scan), Only CONFIRMED (signature engine actively verified), Hide annotated, per-severity show/hide.
- **Exploit playbook**: every finding's detail pane includes concrete attacker-side commands (curl PoCs · sqlmap · Metasploit · nuclei · wpscan · ffuf) with `{target}` already substituted, plus a plain-English *"How an attacker uses this"* paragraph.
- **OWASP + MITRE chips**: every check is tagged with its OWASP Top 10 category (e.g. `A03:2021`) and MITRE ATT&CK technique (e.g. `T1190`). Shown inline in the GUI and console.
- **Exploit confidence**: each finding carries a confidence badge (HIGH / MED / LOW) separate from severity — `[CONFIRMED]` findings are HIGH; presence of a WAF downgrades unconfirmed findings by one tier.
- **Cancel-mid-scan**: clicking Cancel during the 20-min deep throttle test returns a partial result with what was learned so far.

---

## CLI flag reference (most-used)

```
USAGE: wpsecscan.exe [URL] [options]

Targets:
  URL                          A single site (https://example.com)
  --file FILE                  Newline-separated list of URLs

Output:
  --out PATH                   Output directory or filename stem (default: cwd)
  --json-only                  Suppress HTML
  --html-only                  Suppress JSON
  --csv                        Also write CSV
  --sarif                      Also write SARIF 2.1.0
  --quiet, -q                  Suppress the colored console table (alias: --no-console)
  -v / -vv                     Increase console verbosity (per-check / HTTP-level)

Modes:
  --aggressive                 Enable active payload checks (SQLi, XSS, SSRF, etc.)
  --prove                      For each confirmed aggressive finding, run a read-only
                               proof extractor. Requires --aggressive. Read-only.
  --deep-throttle              Run the deep login-throttle mapper
  --deep-throttle-attempts N   (10-500, default 120)
  --deep-throttle-pacing S     (5-60 seconds, default 10)
  --auth-user USER             Admin username for authenticated scan (env: WPSECSCAN_AUTH_USER)
  --auth-pass PASS             Admin password (env: WPSECSCAN_AUTH_PASS; use `-` to read from stdin)
  --ssh-audit user@host        Connect via SSH and run a read-only wp-cli audit
  --password-audit FILE        Offline: convert wp_users dump to a hashcat-ready file (NO network)

Tuning:
  --timeout SECONDS            Per-request timeout (default 15)
  --concurrency N              Concurrent requests per host (default 10)
  --user-agent STRING          Custom User-Agent
  --insecure                   Don't verify TLS certs
  --wpscan-token TOKEN         WPScan API token (richer plugin CVE data)
  --hibp-token TOKEN           HaveIBeenPwned API key

Maintenance:
  --update-db                  Refresh the Wordfence vulnerability database
                               (exits 75 on remote-fetch failure for CI detection)
  --diff OLD.json NEW.json     Diff two saved JSON reports
  --baseline BASELINE.json     Diff scan-in-progress against a saved baseline (alias: --diff-against)
  --debug                      Verbose internal logging to ~/.wpsecscan/logs/
  --completion {bash,zsh,powershell}   Print shell-completion script and exit
  --version

Subcommands (run `wpsecscan <subcommand> --help` for details):
  sites          Manage a list of sites (add/list/scan/remove)
  schedule       Install/uninstall a Windows-Scheduler / launchd / systemd cron
  digest         Configure SMTP / webhook digests of new findings
  ai-cost        Print AI-triage cost summary
  ai-options     Read/set Advanced AI-triage toggles
  analytics      Manage opt-in analytics
  db             vuln DB management (status / update / signatures / source-stats / subscribe / alert-check)
  compare URL    Diff the two most-recent saved snapshots of a URL
  badge URL      Emit a shields.io-style SVG of the latest scan grade
```

---

## Configuration files

Everything is stored in `~/.wpsecscan/` (i.e. `C:\Users\<you>\.wpsecscan\`):

| Path                                         | Purpose                                                  |
|----------------------------------------------|----------------------------------------------------------|
| `history.json`                               | Last 20 scanned URLs (GUI dropdown)                      |
| `profiles.json`                              | Named scan profiles (toggles + deep-throttle settings)   |
| `settings.json`                              | Tokens saved via the GUI onboarding wizard               |
| `sites.json`                                 | Managed-sites list for `wpsecscan sites` + scheduling    |
| `schedule_state.json`                        | Cron-style state for `wpsecscan schedule`                |
| `digest.json`                                | Configured SMTP / webhook digest destinations            |
| `annotations.json`                           | Per-finding annotations (accepted-risk / FP)             |
| `comments.json`                              | Per-finding free-text comments                           |
| `stars.json`                                 | Starred findings (GUI sidebar)                           |
| `disabled_checks.json`                       | Persistently disabled check IDs                          |
| `reports/{host}.json`                        | Latest-scan snapshot per URL (canonical)                 |
| `reports/{host}-{YYYYmmdd-HHMMSS}.json`      | Timestamped snapshot history (for `compare`, trend)      |
| `cache/wporg/{slug}.json`                    | 24h-cached wp.org plugin metadata (plugin_cemetery)      |
| `checkpoints/`                               | `--checkpoint` resumable scan state                      |
| `logs/`                                      | `--debug` log files                                      |
| `demo/`                                      | `--demo` synthetic-scan artifacts                        |
| `analytics/events.jsonl`                     | Opt-in analytics (off by default; `wpsecscan analytics`) |
| `wordfence.json`                             | Local cache of the aggregated CVE database               |

Override the base dir with the `WPSECSCAN_HOME` environment variable.

### Shell completions

```powershell
# bash
wpsecscan --completion bash > /etc/bash_completion.d/wpsecscan

# zsh
wpsecscan --completion zsh > "${fpath[1]}/_wpsecscan"

# PowerShell
wpsecscan --completion powershell | Out-File -Append $PROFILE
```

Restart the shell to activate.

### Secrets via env vars

Every sensitive flag — `--auth-pass`, `--auth-app-password`,
`--companion-token`, `--proxy-auth`, `--wpscan-token`,
`--patchstack-token`, `--hibp-token`, `--vt-token`, `--abuseipdb-token`,
`--github-search-token` — reads from a matching `WPSECSCAN_<UPPER>`
environment variable when not passed on the CLI. Use `--auth-pass -`
to read the password from stdin via `getpass` (stops it leaking into
`ps aux` / shell history).

---

## Safety

- **Use only on sites you own** or have written permission to test. Online password
  brute-force is permanently out of scope. The "deep throttle" probe uses a synthetic
  non-existent username and a fixed wrong password — it maps your defense, it does
  not guess passwords.
- All active payloads are read-only. The payload library is enforced at load-time
  with a pytest invariant that scans for any write-side operations.
- The webhook URL allow-list rejects raw IPs, internal addresses (incl. AWS metadata
  at `169.254.169.254`), and unknown hosts.
- Authenticated scans run with the credentials you provide but never log them.
- The scheduled-task URL validator enforces a strict regex to prevent shell-meta
  injection in the registered `schtasks` command.

---

## Troubleshooting

**"Windows protected your PC" SmartScreen warning** — click *More info → Run anyway*.
The binaries aren't code-signed.

**Defender quarantines `wpsecscan.exe` with `Backdoor:JS/Chopper.GG!dha`** — known false positive.
This is a defensive scanner: to **detect** webshells (China Chopper, c99, r57) on your sites
it ships references to those attack patterns. Defender's pattern-matching heuristic flags
the .exe even though it never executes any of those patterns locally. The same kind of
detection trips sqlmap, Metasploit, nuclei, and Gophish — all legitimate security tools.

**Three ways to fix it:**

1. **In the GUI**: a dialog pops up on first launch with an "Add exclusion now (UAC)"
   button. You can also open it any time via *Tools → Add Windows Defender exclusion...*

2. **From admin PowerShell** (manual, one line):
   ```powershell
   Add-MpPreference -ExclusionPath 'C:\path\to\dist'
   ```
   Replace `C:\path\to\dist` with the actual folder containing the `.exe` binaries.

3. **Via the bundled helper script** (auto-detects the binary location, prompts UAC):
   ```powershell
   .\scripts\add-defender-exclusion.ps1
   ```

**To restore a quarantined file**: *Windows Security → Virus & threat protection →
Protection history → Allow*.

**This program does NOT**:
- Install a backdoor on your computer.
- Open any listening port on your machine.
- Send data anywhere except to the WordPress URLs you type in.
- Run any of the webshells in its signature list — those are strings used to RECOGNISE
  webshells on *your sites*, not to execute them.

**"DB: not loaded — click Refresh"** in the GUI — click *Refresh vuln DB*. Or from the CLI: `wpsecscan.exe --update-db`.

**Scan stalls on a hung target** — `--timeout 5` cuts the per-request wait.

**Multi-target scan freezes for one bad URL** — each URL has its own per-request
timeout. If one consistently hangs, drop it from the list.

**Cron / scheduled-task entries pile up** — list them with `schtasks /Query /TN WPSecScan_*` and remove individually with `schtasks /Delete /TN <name> /F`.

**GUI crashes immediately on launch** — check `C:\Users\<you>\.wpsecscan\` is writable.
Run from a terminal to see the traceback: `wpsecscan-gui.exe` (the windowed
build suppresses console output by design — run via `python run_gui.py` from a checkout
to see errors).

---

## Inventory

| Category                  | Count |
|---------------------------|-------|
| Checks                    | **226** |
| Payloads                  | **224** |
| Exploit signatures        | **307** |
| Plugin CVE database       | ~7,000 (Wordfence) + 7 other sources via the nightly aggregator |
| Exploit-playbook entries  | **25** |
| Tests                     | **667** |

---

## License & disclaimer

Licensed under **AGPLv3+** (from v1.9.0 onward — v1.0.0..v1.8.0 were MIT).
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

**AGPL network clause**: if you run a modified WPSecScan as a hosted service
(SaaS, web UI, paid scanning tier), you must publish your modified source
under the same AGPLv3+ terms. Private internal use and modifications stay
private. For commercial-distribution licensing terms outside AGPLv3,
contact bryaninbangkok@gmail.com.

This tool is for **defensive use** on sites you own. Use against third-party
sites without explicit written permission is illegal in most jurisdictions
under the Computer Fraud and Abuse Act (US) / Computer Misuse Act (UK) /
equivalent laws elsewhere.

The authors take no responsibility for misuse.
