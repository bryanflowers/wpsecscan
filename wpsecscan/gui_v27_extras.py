"""v2.7.0 GUI extras (E72-E80).

Lightweight Tk helpers the main GUI imports + wires from menus and the
findings panel. Each function is small and self-contained.

  E72 fix_it_copy(finding)             — Copy the canonical fix command.
  E73 SiteHealthGauge(parent, score)   — Circular SVG-styled gauge widget.
  E74 inline_diff_highlight(...)       — Color-coded diff vs prior evidence.
  E75 offer_pin_to_taskbar()           — First-launch Windows-only wizard.
  E76 show_changelog_window(parent)    — Reads CHANGELOG.md head section.
  E77 FilterChips(parent, on_change)   — Severity / OWASP filter chips.
  E78 toggle_bookmark(finding)         — ~/.wpsecscan/bookmarks.json CRUD.
  E79 site_colour_tag(target)          — Persisted colour per site.
  E80 OnboardingTour(parent)           — 5-step first-launch tooltip tour.
"""
from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _load_json(name: str, default):
    p = _home() / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _save_json(name: str, data) -> None:
    p = _home() / name
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# E72 — one-click "fix it for me" clipboard copy
# ---------------------------------------------------------------------------

def fix_it_copy(root: tk.Tk, finding) -> str:
    """Copy the canonical fix command to the clipboard. Returns the
    text that was copied."""
    text = finding.remediation or finding.title
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
    except tk.TclError:
        pass
    return text


# ---------------------------------------------------------------------------
# E73 — circular site-health gauge
# ---------------------------------------------------------------------------

class SiteHealthGauge(tk.Canvas):
    """Compact circular gauge: 0=red, 100=green."""
    def __init__(self, parent, score: int = 0, *, size: int = 120, **kw):
        super().__init__(parent, width=size, height=size, highlightthickness=0,
                          bg=kw.pop("bg", "#0d1117"), **kw)
        self._size = size
        self.set_score(score)

    def set_score(self, score: int) -> None:
        self.delete("all")
        s = max(0, min(100, int(score)))
        cx = cy = self._size // 2
        radius = self._size // 2 - 8
        # Background ring
        self.create_oval(cx - radius, cy - radius, cx + radius, cy + radius,
                          outline="#30363d", width=10)
        # Arc proportional to score
        if s > 0:
            color = "#67c069" if s >= 80 else ("#e3b341" if s >= 50 else "#e74c3c")
            self.create_arc(cx - radius, cy - radius, cx + radius, cy + radius,
                              start=90, extent=-3.6 * s,
                              outline=color, width=10, style="arc")
        # Score number
        self.create_text(cx, cy - 6, text=str(s),
                          fill="#c9d1d9",
                          font=("Segoe UI", int(self._size / 4), "bold"))
        self.create_text(cx, cy + 18, text="/100",
                          fill="#8b949e", font=("Segoe UI", 10))


# ---------------------------------------------------------------------------
# E74 — inline diff highlighter
# ---------------------------------------------------------------------------

def inline_diff_highlight(widget: tk.Text, prev: str, current: str) -> None:
    """Render `current` into `widget` with green/red highlighting vs `prev`.
    Uses line-level diff (cheap, no difflib dependency at runtime)."""
    widget.delete("1.0", tk.END)
    widget.tag_config("added",   foreground="#52c41a")
    widget.tag_config("removed", foreground="#ff4d4f")
    widget.tag_config("same",    foreground="#c9d1d9")
    prev_lines = set(prev.splitlines())
    cur_lines = current.splitlines()
    prev_only = set(prev_lines)
    for line in cur_lines:
        if line in prev_only:
            widget.insert(tk.END, line + "\n", "same")
        else:
            widget.insert(tk.END, "+ " + line + "\n", "added")
    for line in prev_lines - set(cur_lines):
        widget.insert(tk.END, "- " + line + "\n", "removed")


# ---------------------------------------------------------------------------
# E75 — pin-to-taskbar wizard (Windows-only)
# ---------------------------------------------------------------------------

def offer_pin_to_taskbar() -> tuple[bool, str]:
    """Best-effort: create a Start-menu shortcut on Windows. Returns
    (ok, message). No-op on macOS / Linux (the OSes handle their own
    'pin to dock' UX)."""
    if sys.platform != "win32":
        return False, "Pin-to-taskbar is Windows-only; macOS/Linux use OS-native pin."
    try:
        import winreg  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False, "winreg unavailable"
    start_menu = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    if not start_menu.exists():
        return False, "Start Menu Programs folder not found"
    target = (Path(sys.executable).parent / "wpsecscan-gui.exe")
    if not target.exists():
        return False, f"wpsecscan-gui.exe not found at {target}"
    # Use PowerShell to create the .lnk (no pywin32 dependency).
    import subprocess
    lnk = start_menu / "WPSecScan.lnk"
    ps_cmd = (
        f"$ws = New-Object -ComObject WScript.Shell; "
        f"$lnk = $ws.CreateShortcut('{lnk}'); "
        f"$lnk.TargetPath = '{target}'; "
        f"$lnk.Save()"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                        capture_output=True, timeout=10, check=False)
        if lnk.exists():
            return True, f"shortcut created: {lnk}"
        return False, "powershell ran but shortcut didn't appear"
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"powershell error: {e}"


# ---------------------------------------------------------------------------
# E76 — in-app changelog viewer
# ---------------------------------------------------------------------------

def show_changelog_window(parent: tk.Tk) -> None:
    """Open a Toplevel showing the top section of CHANGELOG.md."""
    win = tk.Toplevel(parent)
    win.title("What's new")
    win.geometry("700x500")
    text = tk.Text(win, wrap="word", bg="#0d1117", fg="#c9d1d9",
                    font=("Segoe UI", 10), padx=14, pady=14)
    text.pack(fill="both", expand=True)
    # Find CHANGELOG.md alongside the package
    candidates = [
        Path(__file__).parent.parent / "CHANGELOG.md",
        Path.cwd() / "CHANGELOG.md",
    ]
    body = ""
    for p in candidates:
        if p.exists():
            try:
                full = p.read_text(encoding="utf-8")
                # Show top ~80 lines (latest release section)
                body = "\n".join(full.splitlines()[:80])
                break
            except OSError:
                pass
    text.insert("1.0", body or "CHANGELOG.md not found.")
    text.config(state="disabled")


# ---------------------------------------------------------------------------
# E77 — findings filter chips
# ---------------------------------------------------------------------------

class FilterChips(tk.Frame):
    """Severity + OWASP chip filters. Calls `on_change(active_set)` when
    any chip is toggled. Active set is a frozenset of chip labels."""
    DEFAULT_CHIPS = ("critical", "high", "medium", "low", "info",
                      "A01", "A03", "A05", "A07", "A10")

    def __init__(self, parent, on_change, **kw):
        super().__init__(parent, **kw)
        self._on_change = on_change
        self._states: dict[str, tk.BooleanVar] = {}
        for chip in self.DEFAULT_CHIPS:
            var = tk.BooleanVar(value=False)
            self._states[chip] = var
            cb = tk.Checkbutton(self, text=chip, variable=var,
                                 command=self._fire, padx=4, pady=2,
                                 relief="ridge")
            cb.pack(side="left", padx=2)

    def _fire(self):
        active = frozenset(name for name, var in self._states.items() if var.get())
        try:
            self._on_change(active)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# E78 — bookmark a finding
# ---------------------------------------------------------------------------

def toggle_bookmark(finding) -> bool:
    """Add/remove the (check_id, title) tuple in bookmarks.json. Returns
    the new state (True = bookmarked)."""
    marks = _load_json("bookmarks.json", [])
    key = {"check_id": getattr(finding, "check_id", ""),
            "title": getattr(finding, "title", "")}
    for i, m in enumerate(marks):
        if m.get("check_id") == key["check_id"] and m.get("title") == key["title"]:
            marks.pop(i)
            _save_json("bookmarks.json", marks)
            return False
    marks.append(key)
    _save_json("bookmarks.json", marks)
    return True


def list_bookmarks() -> list[dict]:
    return _load_json("bookmarks.json", [])


# ---------------------------------------------------------------------------
# E79 — per-site colour tag
# ---------------------------------------------------------------------------

def site_colour(target: str, *, new: str | None = None) -> str | None:
    """Get or set the operator-assigned colour for `target`."""
    colours = _load_json("site-colours.json", {})
    if new is not None:
        colours[target] = new
        _save_json("site-colours.json", colours)
        return new
    return colours.get(target)


# ---------------------------------------------------------------------------
# E80 — onboarding tour (first-launch only)
# ---------------------------------------------------------------------------

_TOUR_STEPS = [
    ("Welcome to WPSecScan",
     "WPSecScan scans a WordPress site for common security issues. "
     "Authorized testing only. Press Next to learn the main panels."),
    ("Start a scan",
     "Type a URL in the top bar and press Scan. The dashboard fills in "
     "as checks complete — usually 30-90 seconds."),
    ("Read a finding",
     "Click any row in the table to see evidence + remediation. "
     "Critical (red) and high (orange) are most urgent."),
    ("Reports",
     "After a scan, find the HTML/PDF/JSON reports in the output dir. "
     "The CLI 'wpsecscan' command shares the same engine."),
    ("Help",
     "Tools menu → 'What's new' shows the latest changes. "
     "Documentation lives at github.com/bryanflowers/wpsecscan."),
]


class OnboardingTour:
    """Sequential modal tooltip-style tour. Only shows on first launch
    (gated by `~/.wpsecscan/onboarding-shown` sentinel file)."""

    def __init__(self, parent: tk.Tk):
        self._parent = parent
        self._step = 0

    @classmethod
    def should_show(cls) -> bool:
        return not (_home() / "onboarding-shown").exists()

    def show(self):
        if not self.should_show():
            return
        self._win = tk.Toplevel(self._parent)
        self._win.title("Welcome")
        self._win.geometry("420x180")
        self._title = tk.Label(self._win, text="", font=("Segoe UI", 13, "bold"))
        self._title.pack(pady=(10, 4))
        self._body = tk.Label(self._win, text="", wraplength=380, justify="left")
        self._body.pack(padx=12, pady=4)
        nav = tk.Frame(self._win)
        nav.pack(side="bottom", pady=10)
        tk.Button(nav, text="Skip", command=self._dismiss).pack(side="left", padx=4)
        self._next_btn = tk.Button(nav, text="Next ▶", command=self._advance)
        self._next_btn.pack(side="left", padx=4)
        self._render()

    def _render(self):
        title, body = _TOUR_STEPS[self._step]
        self._title.config(text=f"{title}  ({self._step + 1}/{len(_TOUR_STEPS)})")
        self._body.config(text=body)
        self._next_btn.config(text="Done ✓" if self._step == len(_TOUR_STEPS) - 1 else "Next ▶")

    def _advance(self):
        self._step += 1
        if self._step >= len(_TOUR_STEPS):
            self._dismiss()
        else:
            self._render()

    def _dismiss(self):
        try:
            (_home() / "onboarding-shown").parent.mkdir(parents=True, exist_ok=True)
            (_home() / "onboarding-shown").write_text("v2.7.0", encoding="utf-8")
        except OSError:
            pass
        self._win.destroy()
