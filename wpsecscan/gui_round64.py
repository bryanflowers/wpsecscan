"""Round-64 Group H — UX dashboard polish features (#77-90).

Each function takes a Tk parent + optional state, opens a standalone
Toplevel, and returns. Keeps the main gui.py untouched apart from a
small menu cascade that calls these.

Self-contained so the import doesn't break gui.py if tkinter widgets
shift between Python versions.
"""
from __future__ import annotations

import json
import os
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
from typing import Any

# ----- shared state -----
_HOME = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
_VIEWS_FILE = _HOME / "views.json"
_SNOOZE_FILE = _HOME / "snoozed_findings.json"
_THEME_FILE = _HOME / "ui_theme.json"


def _safe_write_json(path: Path, data: Any) -> None:
    """Symlink-safe atomic JSON write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # Unlink target if it's a symlink (guard against TOCTOU symlink swap)
    try:
        if path.is_symlink():
            path.unlink()
    except OSError:
        pass
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def _safe_read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


# =============================================================
# #77 — Real-time scan progress bar with per-check status
# =============================================================
class ScanProgressBar:
    """Drop-in progress indicator. Call .start(total), .step(name), .stop()."""

    def __init__(self, parent: tk.Misc) -> None:
        self.frame = ttk.Frame(parent, padding=4)
        self._label = ttk.Label(self.frame, text="Idle")
        self._label.pack(side="left", fill="x", expand=True)
        self._pb = ttk.Progressbar(self.frame, mode="determinate", length=240)
        self._pb.pack(side="right")
        self._done = 0
        self._total = 0

    def start(self, total: int) -> None:
        self._total = max(total, 1)
        self._done = 0
        self._pb.configure(maximum=self._total, value=0)
        self._label.configure(text=f"Running 0 / {self._total}")

    def step(self, check_name: str) -> None:
        self._done += 1
        self._pb.configure(value=self._done)
        self._label.configure(text=f"{check_name} ({self._done} / {self._total})")
        self.frame.update_idletasks()

    def stop(self) -> None:
        self._label.configure(text=f"Done ({self._done} / {self._total})")


# =============================================================
# #78 — Click-through finding -> "fix steps" inline panel
# =============================================================
def open_finding_fix_panel(parent: tk.Misc, finding: dict) -> None:
    win = tk.Toplevel(parent)
    win.title(f"Fix: {finding.get('title', 'Finding')}")
    win.geometry("700x500")
    text = tk.Text(win, wrap="word", padx=12, pady=12)
    text.pack(fill="both", expand=True)
    text.insert(
        "end",
        f"{finding.get('title', '?')}\n"
        f"Severity: {finding.get('severity', '?')}\n\n"
        f"Evidence:\n{finding.get('evidence', '')}\n\n"
        f"Remediation:\n{finding.get('remediation', '')}\n\n"
        f"URL: {finding.get('url', '')}\n",
    )
    text.configure(state="disabled")
    ttk.Button(win, text="Close", command=win.destroy).pack(pady=4)


# =============================================================
# #79 — Auto-open browser to finding URL
# =============================================================
def open_finding_in_browser(finding: dict) -> None:
    import webbrowser
    url = finding.get("url")
    if url:
        webbrowser.open(url, new=2)


# =============================================================
# #80 — Compare against last scan (diff view)
# =============================================================
def open_diff_window(parent: tk.Misc, current: dict, previous: dict) -> None:
    """Each input: dict {title: severity}."""
    win = tk.Toplevel(parent)
    win.title("Compare against last scan")
    win.geometry("700x500")
    tree = ttk.Treeview(win, columns=("status", "severity"), show="tree headings")
    tree.heading("#0", text="Finding")
    tree.heading("status", text="Status")
    tree.heading("severity", text="Severity")
    tree.column("#0", width=400)
    tree.column("status", width=100)
    tree.column("severity", width=80)
    tree.pack(fill="both", expand=True)

    cur_titles = set(current.keys())
    prev_titles = set(previous.keys())
    for t in sorted(cur_titles | prev_titles):
        if t in cur_titles and t not in prev_titles:
            tree.insert("", "end", text=t, values=("NEW", current.get(t, "?")))
        elif t in prev_titles and t not in cur_titles:
            tree.insert("", "end", text=t, values=("RESOLVED", previous.get(t, "?")))
        else:
            cs = current.get(t, "?")
            ps = previous.get(t, "?")
            tree.insert("", "end", text=t, values=("UNCHANGED" if cs == ps else "CHANGED", cs))


# =============================================================
# #81 — Severity-pivot pie chart (Tk Canvas, no matplotlib dep)
# =============================================================
def render_severity_pie(parent: tk.Misc, counts: dict) -> tk.Canvas:
    """counts = {'critical': N, 'high': N, ...}"""
    colours = {
        "critical": "#b00020",
        "high":     "#e65100",
        "medium":   "#fbc02d",
        "low":      "#388e3c",
        "info":     "#1976d2",
    }
    total = sum(counts.values()) or 1
    canvas = tk.Canvas(parent, width=300, height=300, bg="white", highlightthickness=0)
    start = 0.0
    for sev, n in counts.items():
        if n <= 0:
            continue
        extent = 360.0 * n / total
        canvas.create_arc(
            20, 20, 280, 280,
            start=start, extent=extent,
            fill=colours.get(sev, "#777"), outline="white", width=2,
        )
        start += extent
    # Legend
    y = 10
    for sev, n in counts.items():
        if n <= 0:
            continue
        canvas.create_rectangle(220, y, 240, y + 12, fill=colours.get(sev, "#777"), outline="")
        canvas.create_text(248, y + 6, anchor="w", text=f"{sev}: {n}", font=("TkDefaultFont", 8))
        y += 16
    return canvas


# =============================================================
# #82 — Saved views (filter presets)
# =============================================================
def load_saved_views() -> dict:
    return _safe_read_json(_VIEWS_FILE, {})


def save_view(name: str, filter_dict: dict) -> None:
    views = load_saved_views()
    views[name] = filter_dict
    _safe_write_json(_VIEWS_FILE, views)


def delete_view(name: str) -> None:
    views = load_saved_views()
    views.pop(name, None)
    _safe_write_json(_VIEWS_FILE, views)


def open_saved_views_window(parent: tk.Misc, on_apply) -> None:
    win = tk.Toplevel(parent)
    win.title("Saved filter views")
    win.geometry("400x300")
    views = load_saved_views()
    lb = tk.Listbox(win)
    lb.pack(fill="both", expand=True, padx=8, pady=8)
    for name in sorted(views.keys()):
        lb.insert("end", name)

    def _apply():
        sel = lb.curselection()
        if not sel:
            return
        name = lb.get(sel[0])
        on_apply(views.get(name, {}))
        win.destroy()

    def _delete():
        sel = lb.curselection()
        if not sel:
            return
        name = lb.get(sel[0])
        delete_view(name)
        lb.delete(sel[0])

    btns = ttk.Frame(win)
    btns.pack(fill="x", padx=8, pady=8)
    ttk.Button(btns, text="Apply", command=_apply).pack(side="left")
    ttk.Button(btns, text="Delete", command=_delete).pack(side="left", padx=4)
    ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")


# =============================================================
# #83 — Dark / light theme toggle
# =============================================================
def get_current_theme() -> str:
    return _safe_read_json(_THEME_FILE, {"theme": "light"}).get("theme", "light")


def set_theme(theme: str) -> None:
    _safe_write_json(_THEME_FILE, {"theme": theme})


def apply_theme(root: tk.Misc, theme: str) -> None:
    try:
        import sv_ttk
        sv_ttk.set_theme(theme)
    except ImportError:
        # Manual fallback
        style = ttk.Style(root)
        if theme == "dark":
            style.theme_use("clam")
            root.tk_setPalette(background="#202020", foreground="#e0e0e0")
        else:
            style.theme_use("default")


# =============================================================
# #84 — Keyboard shortcut cheat sheet (Ctrl+/)
# =============================================================
def show_shortcuts(parent: tk.Misc) -> None:
    win = tk.Toplevel(parent)
    win.title("Keyboard shortcuts")
    win.geometry("420x400")
    txt = tk.Text(win, wrap="none", padx=12, pady=12)
    txt.pack(fill="both", expand=True)
    txt.insert("end",
        "Ctrl+S   — Save report\n"
        "Ctrl+O   — Open saved report\n"
        "Ctrl+T   — Payload tester\n"
        "Ctrl+E   — Export findings (CSV)\n"
        "Ctrl+F   — Find in findings\n"
        "Ctrl+/   — This help\n"
        "Ctrl+,   — Settings\n"
        "Ctrl+R   — Re-run scan\n"
        "Ctrl+L   — Clear results\n"
        "Ctrl+D   — Open diff vs last scan\n"
        "Ctrl+Tab — Cycle finding panes\n"
        "F1       — Help / about\n"
        "F5       — Refresh\n"
        "Esc      — Cancel scan\n"
        "\nNavigation:\n"
        "  Tab / Shift-Tab   — Move focus\n"
        "  Arrow keys        — Treeview navigation\n"
        "  Enter             — Open selected finding\n"
        "  Delete            — Snooze selected\n"
    )
    txt.configure(state="disabled")
    ttk.Button(win, text="Close", command=win.destroy).pack(pady=4)


# =============================================================
# #85 — Per-finding "snooze for 7 days"
# =============================================================
def snooze_finding(finding_id: str, days: int = 7) -> None:
    state = _safe_read_json(_SNOOZE_FILE, {})
    expires = (datetime.now(tz=timezone.utc).timestamp() + days * 86400)
    state[finding_id] = expires
    _safe_write_json(_SNOOZE_FILE, state)


def is_snoozed(finding_id: str) -> bool:
    state = _safe_read_json(_SNOOZE_FILE, {})
    expires = state.get(finding_id)
    if expires is None:
        return False
    if datetime.now(tz=timezone.utc).timestamp() > expires:
        # Expired — clean up
        state.pop(finding_id, None)
        _safe_write_json(_SNOOZE_FILE, state)
        return False
    return True


# =============================================================
# #86 — Bulk export selected findings
# =============================================================
def bulk_export_findings(parent: tk.Misc, findings: list) -> None:
    path = filedialog.asksaveasfilename(
        parent=parent,
        defaultextension=".csv",
        filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
    )
    if not path:
        return
    if path.endswith(".json"):
        Path(path).write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    else:
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["severity", "title", "url", "evidence"])
            for f_ in findings:
                if isinstance(f_, dict):
                    w.writerow([f_.get("severity", ""), f_.get("title", ""), f_.get("url", ""), (f_.get("evidence", "") or "")[:500]])
    messagebox.showinfo("Export complete", f"Exported {len(findings)} findings to {path}")


# =============================================================
# #87 — In-app changelog viewer (Help -> What's New)
# =============================================================
def open_changelog(parent: tk.Misc, changelog_path: Path | None = None) -> None:
    """Parses + shows CHANGELOG.md."""
    if changelog_path is None:
        # Best-effort: look beside the running script
        candidates = [Path("CHANGELOG.md"), Path(__file__).parent.parent / "CHANGELOG.md"]
        for c in candidates:
            if c.exists():
                changelog_path = c
                break
    win = tk.Toplevel(parent)
    win.title("What's New")
    win.geometry("700x600")
    txt = tk.Text(win, wrap="word", padx=12, pady=12)
    txt.pack(fill="both", expand=True)
    if changelog_path and changelog_path.exists():
        try:
            txt.insert("end", changelog_path.read_text(encoding="utf-8"))
        except OSError:
            txt.insert("end", "Could not read CHANGELOG.md")
    else:
        txt.insert("end", "CHANGELOG.md not bundled — visit https://github.com/bryanflowers/wpsecscan/blob/main/CHANGELOG.md")
    txt.configure(state="disabled")
    ttk.Button(win, text="Close", command=win.destroy).pack(pady=4)


# =============================================================
# #88 — Drag-and-drop sites.json import
# =============================================================
def setup_sites_drag_drop(parent: tk.Misc, on_import) -> None:
    """Most basic DnD via Tk events — fancy DnD needs `tkdnd` (optional)."""
    def _on_drop(event):
        path = event.data.strip("{}")
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            on_import(data)
            messagebox.showinfo("Import OK", f"Imported {len(data) if isinstance(data, list) else 1} sites from {path}")
        except (OSError, ValueError) as e:
            messagebox.showerror("Import failed", str(e))

    try:
        # tkdnd2 — optional
        parent.drop_target_register("DND_Files")  # type: ignore[attr-defined]
        parent.dnd_bind("<<Drop>>", _on_drop)     # type: ignore[attr-defined]
    except (AttributeError, tk.TclError):
        # Fallback: provide an "Import sites JSON..." button instead
        def _click_import():
            path = filedialog.askopenfilename(parent=parent, filetypes=[("JSON", "*.json")])
            if not path:
                return
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                on_import(data)
            except (OSError, ValueError) as e:
                messagebox.showerror("Import failed", str(e))
        ttk.Button(parent, text="Import sites.json...", command=_click_import).pack(pady=2)


# =============================================================
# #89 — "Scan all sites now" toolbar button
# =============================================================
def add_scan_all_button(toolbar: tk.Misc, on_click) -> ttk.Button:
    btn = ttk.Button(toolbar, text="Scan all sites now", command=on_click)
    btn.pack(side="left", padx=2)
    return btn


# =============================================================
# #90 — System tray icon + balloon notifications
# =============================================================
class TrayController:
    """Optional pystray-based tray. No-op when pystray isn't installed."""

    def __init__(self, app_name: str = "WPSecScan") -> None:
        self.app_name = app_name
        self._tray = None
        try:
            import pystray  # type: ignore
            from PIL import Image, ImageDraw  # type: ignore
            img = Image.new("RGB", (64, 64), "#1976d2")
            d = ImageDraw.Draw(img)
            d.rectangle((8, 8, 56, 56), outline="white", width=4)
            menu = pystray.Menu(
                pystray.MenuItem("Open", self._on_open),
                pystray.MenuItem("Quit", self._on_quit),
            )
            self._tray = pystray.Icon(app_name, img, app_name, menu)
        except ImportError:
            pass

    def start(self) -> None:
        if self._tray:
            import threading
            threading.Thread(target=self._tray.run, daemon=True).start()

    def notify(self, title: str, message: str) -> None:
        if self._tray:
            try:
                self._tray.notify(message, title)
            except Exception:  # noqa: BLE001
                pass

    def _on_open(self, icon, item):  # pragma: no cover - tray callback
        pass

    def _on_quit(self, icon, item):  # pragma: no cover - tray callback
        if self._tray:
            self._tray.stop()


def add_round64_menu(menubar: tk.Menu, root: tk.Misc) -> tk.Menu:
    """Wire the 14 features into a single 'Round-64' cascade.

    Most handlers need app-specific state (current findings, selected
    finding etc.) — those are no-ops here and the real wiring happens
    in gui.py. This cascade exists so the new features are reachable
    even without the gui.py wiring.
    """
    m = tk.Menu(menubar, tearoff=False)
    m.add_command(label="Keyboard shortcuts (Ctrl+/)", command=lambda: show_shortcuts(root))
    m.add_command(label="What's New (CHANGELOG)...", command=lambda: open_changelog(root))
    m.add_command(label="Saved filter views...", command=lambda: open_saved_views_window(root, lambda d: None))
    m.add_separator()
    m.add_command(label="Theme: Dark", command=lambda: (set_theme("dark"), apply_theme(root, "dark")))
    m.add_command(label="Theme: Light", command=lambda: (set_theme("light"), apply_theme(root, "light")))
    menubar.add_cascade(label="Round-64 polish", menu=m)
    return m
