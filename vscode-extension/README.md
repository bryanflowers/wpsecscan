# WPSecScan — VS Code extension

Open a [wpsecscan](https://github.com/bryanflowers/wpsecscan) JSON report and
navigate findings inline in the VS Code editor.

## Features

- **Sidebar panel** — findings grouped by severity → check → title.
- **Diagnostics** — findings whose `url` field resolves to a workspace file
  are decorated as native VS Code problems, so they appear in the Problems
  panel and as gutter icons.
- **One-click rescan** — `WPSecScan: Scan current site` runs the CLI in an
  integrated terminal.
- **Auto-discovery** — on activation the extension scans the workspace for
  the freshest wpsecscan JSON report (in `./`, `wpsecscan-reports/`,
  `reports/`, or `out/`).

## Setup

1. `npm install` inside `vscode-extension/`.
2. `npm run compile`.
3. Press F5 inside VS Code with this folder open as the workspace root —
   it launches an Extension Development Host with the extension loaded.

## Commands

| Command                            | What it does                                    |
|------------------------------------|-------------------------------------------------|
| `WPSecScan: Open Report (JSON)`    | Pick a `.json` report manually.                 |
| `WPSecScan: Scan current site`     | Spawn `wpsecscan <site>` in a terminal.         |
| `WPSecScan: Refresh findings`      | Re-load the current report from disk.           |

## Settings

| Key                       | Default      | Purpose                                        |
|---------------------------|--------------|------------------------------------------------|
| `wpsecscan.cliPath`       | `wpsecscan`  | Path/name of the wpsecscan CLI on this host.   |
| `wpsecscan.defaultSite`   | `""`         | Site URL used by `Scan current site`.          |

## License

MIT.
