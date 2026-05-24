# GUI walkthrough

Launch: double-click `wpsecscan-gui.exe` (or `python -m wpsecscan.gui`).

## First run

A welcome tour appears (skippable). Covers:
- Where to type the target URL
- How aggressive mode differs
- Tools → Settings for API keys + AI config
- Reports folder

## Layout

```
┌────────────────────────────────────────────────────┐
│ URL: [____________________] [Scan] [Aggressive]    │  ← top bar
├──────────────────┬─────────────────────────────────┤
│ Findings tree    │ Activity log / Live dashboard   │
│  • Critical (2)  │  [09:14:22] core_version probe… │
│  • High (5)      │  [09:14:23] plugins enum: 12    │
│  • Medium (12)   │  [09:14:24] tls_deep handshake… │
│  • Low (8)       │  ...                            │
│  • Info (40)     │                                 │
├──────────────────┴─────────────────────────────────┤
│ Selected finding details (severity, evidence,      │
│ remediation, OWASP/MITRE/compliance chips)         │
└────────────────────────────────────────────────────┘
```

## Menus

**File**: New scan / Open report / Recent / Quit
**Tools**: Settings · Sites manager · Dashboard · Diff · CTF practice · Tutorial
**View**: Theme (6 themes) · Compact mode · Full-screen
**Help**: Tutorial · Check explainer · About · Check for updates

## Settings dialog

- **General**: theme, locale (en/es/fr/de/pt-br/ja/zh-cn), sound pack, quiet hours
- **AI**: API key per backend, opt-in toggle, cost cap
- **Compliance**: default framework
- **Scheduler**: weekly scan time
- **Notifications**: SMTP / Slack webhook for digests
- **Advanced**: WPSECSCAN_HOME override, custom check directory

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| Ctrl+R | Rescan current target |
| Ctrl+E | Export report |
| Ctrl+L | Focus log pane |
| Ctrl+/ | Search findings |
| Ctrl+Shift+P | Command palette |
| Ctrl+Q | Quit |

Vim modal keys also available (h/j/k/l navigation) — enable in Settings.
