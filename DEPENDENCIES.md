# Dependencies

WPSecScan keeps its required dependency tree intentionally small. Every
non-trivial integration is an optional extra so users can install only
what they need.

## Required (4 packages)

| Package | License | Why |
|---------|---------|-----|
| [httpx](https://www.python-httpx.org/) `>=0.27,<0.29` | BSD-3 | Async HTTP client (with `[http2]` for HTTP/2 multiplexing) |
| [Jinja2](https://jinja.palletsprojects.com/) `>=3.1,<4` | BSD-3 | HTML report templating |
| [Rich](https://rich.readthedocs.io/) `>=13.7,<14` | MIT | Console rendering + live multi-panel dashboard |
| [openpyxl](https://openpyxl.readthedocs.io/) `>=3.1,<4` | MIT | Excel (`.xlsx`) export |

## Optional extras

Install with `pip install wpsecscan[<extra>]` or `pip install wpsecscan[all]`.

| Extra      | Packages | What it unlocks |
|------------|----------|-----------------|
| `pdf`      | reportlab | Real PDF executive + attestation reports (otherwise HTML fallback) |
| `browser`  | playwright | Headless DOM-XSS check + per-finding screenshots in HTML report |
| `yaml`     | pyyaml | Daemon mode YAML config parsing |
| `ops`      | redis, bcrypt | Shared CVE-DB cache (Redis) + bcrypt-hashed RBAC tokens (sha256 fallback if absent) |
| `otel`     | opentelemetry-* | One OTLP span per check, shipped to your APM |
| `test`     | pytest | Run the test suite |
| `all`      | every optional package above | One-line "kitchen sink" install |

## Standard library only

These features use only Python stdlib — no extra deps:

- 60-flag argparse CLI
- Async `asyncio` scanner with parallel-group execution
- Tkinter GUI (`wpsecscan-gui.exe`)
- Activity event bus (`activity.py`)
- HTTP API server (`api_server.py`) — uses `http.server`, not FastAPI
- Slack / Discord webhook bot (`chat_bot.py`)
- Audit-log shipping to Splunk HEC / Datadog / Loki — `urllib.request`
- CycloneDX 1.5 SBOM emission — `importlib.metadata`
- HAR recorder + replay
- Cron-style daemon parser (no `croniter` dep)

## Generating an SBOM

For procurement / vendor-risk programs, generate a CycloneDX 1.5 SBOM:

```bash
wpsecscan --sbom out.json
```

This walks `importlib.metadata` and emits every wheel installed in the
running Python environment, including pinned versions + purl identifiers
+ license strings.

## Licence compatibility

All required deps are permissive (BSD-3 or MIT) — compatible with MIT
(WPSecScan's licence). Optional deps:

| Package | Licence | Compatible with MIT? |
|---------|---------|----------------------|
| reportlab    | BSD-3 | yes |
| playwright   | Apache-2.0 | yes |
| pyyaml       | MIT | yes |
| redis-py     | MIT | yes |
| bcrypt       | Apache-2.0 | yes |
| opentelemetry-* | Apache-2.0 | yes |

## Upgrade policy

- Pin loose major boundaries (e.g. `httpx>=0.27,<0.29`) so a breaking
  release doesn't silently break the scanner.
- Test matrix runs against Python 3.10–3.12.
- Dependabot is enabled (see `.github/dependabot.yml`) and PRs are auto-merged
  if `pytest` passes and the diff is patch-level only.

## Reporting a vulnerable dependency

If a dep we use gets a CVE, please open an issue or email
bryaninbangkok@gmail.com — we'll bump the floor and cut a patch release.
