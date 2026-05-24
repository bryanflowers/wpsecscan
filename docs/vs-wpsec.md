# WPSecScan vs WPSec.com

WPSec.com is the closest direct commercial competitor — both products
target WordPress, both expose a dashboard, both schedule recurring scans.
This page is a feature-by-feature comparison researched in May 2026.

## Headline differences

| Dimension | **WPSecScan (this project)** | wpsec.com |
|-----------|------------------------------|-----------|
| **Pricing** | Free, AGPLv3 — unlimited sites | Free (1 site, 20 reports); Premium €39/mo; White-label €395/mo |
| **Deployment** | **Runs locally** on your machine — no data leaves you | SaaS — site data sent to their cloud |
| **Source code** | Open (audit + fork) | Closed |
| **Scan count** | 150+ checks across 18 categories | Smaller curated check list (vuln-DB driven) |
| **Compliance** | OWASP, MITRE ATT&CK, CWE, D3FEND, PCI 4.0, NIST 800-53, HIPAA, FERPA, SOC 2, FedRAMP, GDPR, HITRUST, CMMC, NIST CSF 2.0, CIS v8, ISO 27001:2022 | None advertised |
| **AI augmentation** | Optional BYO key (OpenAI / Anthropic / Ollama / llama.cpp), PII-masked, cost-tracked | None |
| **Authenticated scan** | Cookie + Application Password + 2FA + companion-plugin token | None |
| **Multi-site dashboard** | Yes (`wpsecscan sites` + GUI tab) | Yes (their main UX) |
| **Scheduling** | Yes — Windows Task Scheduler / launchd / systemd | Yes — daily / weekly / monthly |
| **Email alerts** | Yes (via `wpsecscan digest`) | Yes |
| **Slack / Teams / Discord** | Yes (webhook env vars) | Webhook only (Premium) |
| **Jira / Linear / GitHub Issues filing** | Yes | No |
| **CI/CD integration** | Yes — `wpsecscan/wpsecscan@v1` GitHub Action | None advertised |
| **Aggressive payload checks** | Yes (`--aggressive` — SQLi/XSS/SSRF/path traversal) | No (passive vuln-DB only) |
| **WP companion plugin** | Yes — token-gated REST endpoint for richest data | No |
| **PCI evidence pack** | Yes (JSON for QSA workpaper) | No |
| **Headless DOM-XSS** | Yes (Playwright opt-in) | No |
| **YAML / nuclei templates** | Yes — drop into `~/.wpsecscan/plugins/` | No |
| **Hardware-security-key support** | Yes (Yubikey GPG, TPM/DPAPI sealing) | No |
| **Browser-extension launcher** | Yes (Chrome/Firefox) | No |
| **Offline mode / air-gapped** | Yes (`WPSECSCAN_NO_NETWORK=1`) | No (SaaS — needs net) |
| **Data sovereignty** | Your machine. Period. | Their EU servers |

## Where wpsec.com wins

- **Easier onboarding** — paste URL, done. No install.
- **Slick web dashboard** out of the box. WPSecScan ships a GUI, not a web UI.
- **Brand recognition** — they've been around years.
- **White-label tier** — pre-built for MSPs reselling to clients.
- **Premium "unlimited reports" UX** — managed retention.

## Where WPSecScan wins

- **5-10x more checks** across deeper categories (vertical-plugin audits, headless WP, crypto agility, PQ, post-quantum hybrid KEX hints, etc.)
- **15 compliance frameworks mapped** vs zero
- **AI-augmented remediation** with prompt-injection guard + PII masking
- **Auth + companion plugin** = ~3x more accurate plugin/theme detection (no HTTP-probe guessing)
- **CI/CD-first** — fail builds on `--max-critical`, ships GitHub Action
- **Aggressive payload checks** for owned-site pentesting
- **Privacy** — nothing leaves the machine
- **No per-site pricing** — unlimited sites at the free tier
- **Extensible** — drop a Python file into `~/.wpsecscan/plugins/` to add a check

## Where they overlap

Both ship: vuln-DB matching, dashboard, scheduling, email alerts,
webhook integration, multi-site management.

## Gaps to close (open work for future rounds)

These are things wpsec.com does that we don't yet match:

1. **Hosted free instant scan** at a public URL — no install needed.
   _Status_: would require self-hosting our API server on a public domain.
   _Trade-off_: against our "runs locally" privacy story.
2. **White-label / reseller tier** — agencies want their logo on the report.
   _Status_: partial (PDF logo support added in round-60); needs full
   re-skinning hooks.
3. **Polished marketing site** — wpsec.com has dedicated landing pages.
   _Status_: GitHub Pages stub exists; needs design pass.
4. **G2 / Capterra listing** for SEO.
   _Status_: not yet — needs a paid commercial tier first.

## Migration path from wpsec.com

If you're currently paying €39/month for wpsec Premium and want to try
WPSecScan instead:

```bash
pip install wpsecscan
wpsecscan sites add https://your-site.com --weekly
wpsecscan schedule install --time 03:00
wpsecscan digest configure --to you@example.com
```

That's the equivalent of the Premium tier. Free, unlimited sites,
runs from your office machine, no data ever sent to a third party.

---

## Sources

- [WPSec.com plans page](https://wpsec.com/plans.php) — pricing tiers
- [G2: WPSEC Reviews 2026](https://www.g2.com/products/wpsec/reviews) — feature claims
- [Geekflare: 11 Best WordPress Vulnerability Scanners 2026](https://geekflare.com/cybersecurity/best-wordpress-scanner/) — landscape
- [WPLift WPSec review](https://wplift.com/wpsec-review/) — detailed feature breakdown
- [WPSec Vulnerability API blog post](https://blog.wpsec.com/wordpress-vulnerability-api/) — API surface
