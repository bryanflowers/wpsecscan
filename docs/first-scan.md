# Your first scan

## CLI

```
wpsecscan https://example.com
```

Output appears in the terminal. JSON + HTML reports are written to the current directory (change with `--out`).

### Common flags

| Flag | Effect |
|------|--------|
| `--aggressive` | Run aggressive (active payload) checks. **Only on sites you own** — these send actual SQLi / XSS / SSRF probes. They run passive unless the target is marked as owned (`--owned`, `WPSECSCAN_OWNED_TARGETS`, or `wpsecscan owned add <host>`). |
| `wpsecscan only <check_id> <url>` | Run a single check. See [checks/](checks/) for IDs. |
| `wpsecscan check disable <id>` | Skip a check on future scans (`check enable <id>` undoes it). |
| `--demo` | Run with the bundled demo target so you can see every check fire. |
| `--out DIR` | Write the reports to a directory or filename stem. |
| `--json-only` | Write only the JSON report (`--html-only` for only HTML). |
| `--file urls.txt` | Scan a batch of URLs (one per line). |
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
