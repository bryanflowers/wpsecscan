# Keyboard-only WPSecScan GUI walkthrough

Round-64 #103 — every workflow in the GUI is reachable without a
mouse. This page documents the exact key sequences.

## Launching

1. Press `Win` or `Alt` and type `wpsecscan` → `Enter`.
2. Or from a terminal: `wpsecscan-gui` → `Enter`.

## First scan

1. `Tab` focuses the URL input.
2. Type the target URL.
3. `Tab` → focuses **Start scan** button.
4. `Enter` runs it.
5. Findings populate the Treeview. `Tab` enters it. Arrow keys
   navigate; `Enter` expands.

## Snoozing a finding

1. Arrow-down to the finding.
2. `Delete` → snoozes for 7 days.

## Exporting

1. `Ctrl+S` → file-save dialog. Choose format from extension.
2. `Tab` to the filename input. Type, `Enter`.

## Menu navigation

| Key | Result |
|-----|--------|
| `Alt+F` | File menu |
| `Alt+T` | Tools menu |
| `Alt+V` | View menu |
| `Alt+H` | Help menu |
| `Esc` | Close menu / cancel scan |

## Most-used shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+T` | Payload tester |
| `Ctrl+E` | Export findings (CSV) |
| `Ctrl+R` | Re-run scan |
| `Ctrl+D` | Diff vs last scan |
| `Ctrl+/` | Show full shortcuts cheat-sheet |

## Screen-reader mode (CLI)

```bash
wpsecscan --screen-reader scan https://example.com
```

Strips colour + box-drawing + emoji. Outputs one finding per line.

## High-contrast mode (CLI)

```bash
wpsecscan --high-contrast scan https://example.com
```

Bold severity tag, no colour. Compatible with any terminal palette.

## Voice summary

```bash
wpsecscan --voice-summary out.wav scan https://example.com
```

Writes a spoken executive summary. Requires `pip install
wpsecscan[ui]` for pyttsx3.

## Reporting accessibility bugs

Open an issue: <https://github.com/bryanflowers/wpsecscan/issues>
with the label `accessibility`.
