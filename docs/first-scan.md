# Your first scan

## CLI

```
wpsecscan --target https://example.com
```

Output appears in the terminal. JSON + HTML reports land in `./wpsecscan-reports/`.

### Common flags

| Flag | Effect |
|------|--------|
| `--aggressive` | Run aggressive (active payload) checks. **Only on sites you own** — these send actual SQLi / XSS / SSRF probes. |
| `--only <id>` | Run a single check. See [checks/](checks/) for IDs. |
| `--skip <id>` | Skip one or more checks (`--skip plugins,themes`). |
| `--demo` | Run with the bundled demo target so you can see every check fire. |
| `--json out.json` | Write JSON report to a custom path. |
| `--html out.html` | Write HTML report to a custom path. |
| `--target-file urls.txt` | Scan a batch of URLs (one per line). |
| `--compliance-framework hitrust` | Overlay compliance mappings in the report. |
| `--auth-user X --auth-pass Y` | Authenticated scan (see [auth](auth.md)). |

## GUI

Double-click `wpsecscan-gui.exe`.

- Paste the URL into the top bar → click **Scan**.
- Watch the live activity log in the right pane.
- Findings populate the table — click any row for full evidence + remediation.
- **Tools → Settings → AI** to add your OpenAI / Anthropic / Ollama key for
  AI-augmented remediation.
- **Tools → Settings → Compliance** to pick a framework.

## What to do with results

- HTML report has clickable severity filters + per-finding "fix it" snippets
- JSON report is `report.schema.json`-compliant for tooling integration
- Use `--diff old.json new.json` (or the GUI Diff view) to see what changed
- Star findings in the GUI to track which ones you've reviewed
