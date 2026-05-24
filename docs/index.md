# WPSecScan

Defensive WordPress security scanner — **150 checks** across 18 categories,
AI-assisted remediation (BYO key), HITRUST / CMMC / NIST CSF 2.0 / CIS v8 /
ISO 27001:2022 mapping, CLI + GUI, runs locally.

[GitHub](https://github.com/bryanflowers/wpsecscan) · [Latest release](https://github.com/bryanflowers/wpsecscan/releases/latest) · [Issues](https://github.com/bryanflowers/wpsecscan/issues)

## 60-second start

1. [Install](install.md) — download the .exe or pip install
2. [First scan](first-scan.md) — `wpsecscan --target https://yoursite.com`
3. [GUI](gui.md) — double-click `wpsecscan-gui.exe`

## Guides

- [Install + uninstall](install.md)
- [Authenticated scans (login as admin)](auth.md)
- [Weekly auto-scan + dashboard](weekly-scans.md)
- [WP companion plugin](wp-plugin.md) — install in your WordPress for richer data
- [Compliance flows](compliance.md) — PCI 4.0, HITRUST, CMMC, NIST CSF, CIS v8, ISO 27001:2022
- [AI / LLM features](ai.md) — bring your own key, PII-masked
- [CI / CD integration](ci.md)
- [Bug-bounty workflow](bounty.md)

## Reference

- [Every check explained](checks/) — auto-generated from source
- [CLI flags](cli.md)
- [Configuration files](config.md)
- [Plugin authoring (write your own checks)](plugin-authoring.md)

## Why WPSecScan

vs. paid SaaS scanners:
- **runs locally** — no data leaves your machine
- **AGPLv3 + open source** — audit the code, fork it
- **150 checks** vs typical 30-80
- **no per-site pricing** — scan unlimited sites
- **bundled AI** — bring your own OpenAI / Anthropic / Ollama key, no markup
