from __future__ import annotations

import asyncio
import os
import queue
import re
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter
import tkinter as _tk_mod
from tkinter import Tk, StringVar, BooleanVar, IntVar, DoubleVar, END, NORMAL, DISABLED, messagebox
from tkinter import ttk
from urllib.parse import urlparse

from . import __version__
from . import db as vulndb
from .checks import ALL_CHECKS
from .models import CheckResult, ScanReport
from .reporters import csv_out as csv_reporter
from .reporters import html as html_reporter
from .reporters import json_out as json_reporter
from .reporters import sarif as sarif_reporter
from .scanner import scan

APP_NAME = "WPSecScan"

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_COLOR = {
    "critical": "#ff5252",
    "high":     "#ff7b54",
    "medium":   "#f1b94c",
    "low":      "#5ab0f2",
    "info":     "#7a8a99",
}
BG = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1f2630"
FG = "#e6edf3"
MUTED = "#8b949e"
BORDER = "#30363d"
ACCENT = "#2f81f7"


def _safe_host(target: str) -> str:
    host = urlparse(target).hostname or "site"
    return re.sub(r"[^a-z0-9.-]+", "_", host.lower())


class _Tooltip:
    """Lightweight tooltip — pops a small Toplevel near the cursor on hover.

    Used to explain when disabled buttons will become active."""
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, _e=None):
        if self.tip:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tkinter.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tkinter.Label(self.tip, text=self.text, bg="#1f2630", fg="#e6edf3",
                      relief="solid", borderwidth=1,
                      font=("Segoe UI", 9), padx=8, pady=4,
                      justify="left", wraplength=320).pack()

    def _hide(self, _e=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


def _suggest_for_error(err: str) -> str:
    """Map common scan errors to actionable next steps. Returns '' for unknown errors."""
    e = (err or "").lower()
    if "certificate" in e or "ssl" in e or "tls" in e or "self-signed" in e:
        return ("TLS/cert problem detected. If the site uses a self-signed cert or your\n"
                "local environment can't verify the chain, retry from the CLI with --insecure.\n"
                "If the site is supposed to have a valid cert, check it at https://ssllabs.com/")
    if "timed out" in e or "timeout" in e:
        return ("The target didn't respond within 15 s. Try one of:\n"
                "  • Retry now (the site may be slow or rate-limiting you)\n"
                "  • CLI: --timeout 30  to allow up to 30 s per request\n"
                "  • CLI: --concurrency 3  to reduce parallel pressure on the target")
    if "name or service not known" in e or "nodename" in e or "getaddrinfo" in e or "no address" in e:
        return ("DNS lookup failed. Check that the URL is correctly typed and the domain exists.\n"
                "If you're behind a corporate proxy, this scanner doesn't use proxy settings yet —\n"
                "scan from an unproxied network.")
    if "refused" in e or "connection reset" in e:
        return ("The target refused the connection. Common causes:\n"
                "  • The site is offline\n"
                "  • A WAF / firewall is blocking your IP (you may need to allow-list yourself)\n"
                "  • Wrong port — make sure the URL includes :8080 / :443 if non-standard")
    if "429" in e or "rate limit" in e or "too many requests" in e:
        return ("The target returned HTTP 429 (rate limit). Try:\n"
                "  • Wait a few minutes\n"
                "  • CLI: --concurrency 2  to slow the request rate\n"
                "  • If you have a CDN like Cloudflare in front, allow-list your IP")
    if "403" in e or "forbidden" in e:
        return ("The target returned HTTP 403. Likely a WAF blocking the scanner's User-Agent.\n"
                "Try:  --user-agent \"Mozilla/5.0 (compatible; WPSecScan)\"  or allow-list your IP\n"
                "at the WAF.")
    return ""


class App:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title(f"{APP_NAME}  v{__version__}")
        # UX-034: DPI-aware sizing. Without this, on a 4K 27" display the
        # whole UI shrinks to the size of a postage stamp because Tk
        # assumes 96 DPI. We:
        #   1. Mark the process per-monitor DPI-aware (Windows-only API)
        #   2. Compute the effective scale factor from Tk's own DPI probe
        #   3. Tell Tk to scale all point-based fonts and geometry by it
        # All fonts in this file use point sizes (positive int), so Tk
        # scaling correctly enlarges them.
        try:
            import ctypes as _ct
            try:
                _ct.windll.shcore.SetProcessDpiAwareness(1)  # PER_MONITOR_DPI_AWARE
            except (AttributeError, OSError):
                _ct.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass  # not Windows, or already set
        try:
            self._dpi_scale = max(1.0, min(3.0, float(self.root.winfo_fpixels("1i")) / 72.0))
            self.root.tk.call("tk", "scaling", self._dpi_scale)
        except (_tk_mod.TclError, ValueError, ZeroDivisionError):
            self._dpi_scale = 1.0
        # Scale the initial window proportionally so the layout fits.
        base_w, base_h = 1200, 780
        sw = int(base_w * (self._dpi_scale / 1.333))  # 1.333 = 96 DPI baseline
        sh = int(base_h * (self._dpi_scale / 1.333))
        self.root.geometry(f"{max(960, sw)}x{max(600, sh)}")
        self.root.minsize(960, 600)
        self.root.configure(bg=BG)

        self.url_var = StringVar(value="")
        self.auth_user_var = StringVar(value="")
        self.auth_pass_var = StringVar(value="")
        self.search_var = StringVar(value="")
        self.save_reports_var = BooleanVar(value=True)
        self.aggressive_var = BooleanVar(value=False)
        self.prove_var = BooleanVar(value=False)
        self.deep_throttle_var = BooleanVar(value=False)
        from .checks.login_throttle_deep import (
            DEFAULT_ATTEMPTS as _DT_ATTEMPTS_DEFAULT,
            DEFAULT_PACING_SECONDS as _DT_PACING_DEFAULT,
            MIN_ATTEMPTS as _DT_MIN_A, MAX_ATTEMPTS as _DT_MAX_A,
            MIN_PACING_SECONDS as _DT_MIN_P, MAX_PACING_SECONDS as _DT_MAX_P,
        )
        self._DT_BOUNDS = (_DT_MIN_A, _DT_MAX_A, _DT_MIN_P, _DT_MAX_P)
        self.deep_throttle_attempts_var = IntVar(value=_DT_ATTEMPTS_DEFAULT)
        self.deep_throttle_pacing_var = DoubleVar(value=_DT_PACING_DEFAULT)
        # UX-033: per-request HTTP timeout, exposed via Settings.
        self.http_timeout_var = DoubleVar(value=15.0)
        self.deep_throttle_eta_var = StringVar(value="")
        # #12: webhook notify (loaded from a profile if any)
        self.webhook_url_var = StringVar(value="")
        self.webhook_threshold_var = StringVar(value="high")
        # D2: GitHub Issues integration
        self.github_repo_var = StringVar(value="")
        self.github_token_var = StringVar(value="")
        self.github_threshold_var = StringVar(value="high")
        self.github_enabled_var = BooleanVar(value=False)
        # #5: new-since-last-scan finding titles
        self._new_finding_titles: set = set()
        # Side-window singletons
        self._settings_win = None
        self._mt_win = None
        self.show_critical_var = BooleanVar(value=True)
        self.show_high_var = BooleanVar(value=True)
        self.show_medium_var = BooleanVar(value=True)
        self.show_low_var = BooleanVar(value=True)
        # Default OFF: a typical scan emits ~50 info findings that bury actionable ones.
        # User can flip the pill to see them.
        self.show_info_var = BooleanVar(value=False)
        self.db_status_var = StringVar(value="DB: checking...")
        self.status_var = StringVar(value="Ready. Enter a URL and click Scan.")
        self.summary_var = StringVar(value="")
        # #7: persistent toast that lingers ~5s instead of being overwritten in 40ms
        self.toast_var = StringVar(value="")
        self._toast_after_id = None
        self._cancel_requested: bool = False
        # #51: GUI pause/resume — flipped True by _on_pause, polled by scanner.
        self._pause_requested: bool = False

        self._queue: queue.Queue = queue.Queue()
        self._scan_thread: threading.Thread | None = None
        self._current_report: ScanReport | None = None
        self._last_html_path: Path | None = None
        self._last_json_path: Path | None = None
        self._total_checks: int = 0
        self._done_checks: int = 0
        self._check_rows: dict[str, str] = {}
        self._finding_for_iid: dict = {}

        self._build_styles()
        self._build_ui()
        self._refresh_db_status()
        self.root.after(40, self._drain_queue)

    # ---------- UI construction ----------

    def _build_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:  # noqa: BLE001
            pass
        style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL2)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Summary.TLabel", background=PANEL, foreground=FG, padding=8)
        style.configure(
            "TEntry",
            fieldbackground=PANEL2,
            foreground=FG,
            insertcolor=FG,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
        )
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#ffffff",
            bordercolor=ACCENT,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#388bfd"), ("disabled", "#30363d")],
        )
        style.configure(
            "TButton",
            background=PANEL2,
            foreground=FG,
            bordercolor=BORDER,
            padding=(10, 6),
        )
        style.map("TButton", background=[("active", "#2a3340")])
        style.configure(
            "Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=FG,
            bordercolor=BORDER,
            rowheight=24,
        )
        style.configure(
            "Treeview.Heading",
            background=PANEL2,
            foreground=FG,
            bordercolor=BORDER,
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#1f4f8a")])
        style.configure("TProgressbar", background=ACCENT, troughcolor=PANEL2, bordercolor=BORDER)
        style.configure("TCheckbutton", background=BG, foreground=FG)
        # The default ttk theme flips Checkbutton background to system white
        # in the `active` (hover) state but leaves foreground white — so the
        # text disappears against the new white background. Pin both states
        # explicitly so hover stays readable.
        style.map(
            "TCheckbutton",
            background=[("active", BG), ("pressed", BG), ("selected", BG)],
            foreground=[("active", FG), ("pressed", FG), ("disabled", MUTED), ("selected", FG)],
        )
        # Radiobutton has the same problem — same fix.
        style.configure("TRadiobutton", background=BG, foreground=FG)
        style.map(
            "TRadiobutton",
            background=[("active", BG), ("pressed", BG), ("selected", BG)],
            foreground=[("active", FG), ("pressed", FG), ("disabled", MUTED), ("selected", FG)],
        )

    def _build_ui(self) -> None:
        # --- Menu bar ---
        menubar = tkinter.Menu(self.root)
        # File menu with scan profiles
        file_menu = tkinter.Menu(menubar, tearoff=False)
        self._profiles_menu = tkinter.Menu(file_menu, tearoff=False)
        self._rebuild_profiles_menu()
        file_menu.add_cascade(label="Profiles", menu=self._profiles_menu)
        file_menu.add_separator()
        file_menu.add_command(label="Save current settings as profile...", command=self._save_profile_prompt)
        # #55: open a saved JSON report. Tk has no portable drag-drop, so we
        # expose this via menu + Ctrl-O instead.
        file_menu.add_command(label="Open saved JSON report... (Ctrl+O)",
                                command=self._open_saved_report)
        file_menu.add_separator()
        # #13: bulk export of all findings as one markdown document
        file_menu.add_command(label="Export all findings as Markdown...", command=self._export_markdown)
        file_menu.add_separator()
        # #8: consolidated settings window
        file_menu.add_command(label="Settings...", accelerator="Ctrl+,", command=self._open_settings)
        menubar.add_cascade(label="File", menu=file_menu)
        tools = tkinter.Menu(menubar, tearoff=False)
        tools.add_command(label="Payload Tester...", accelerator="Ctrl+T", command=self._open_payload_tester)
        # #1: multi-target window
        tools.add_command(label="Multi-target scan...", command=self._open_multitarget)
        # #2: scheduled scan registration
        tools.add_command(label="Schedule recurring scan...", command=self._open_schedule)
        # #11: trend sparkline window
        tools.add_command(label="Show risk trend for current URL", command=self._open_trend)
        # E8: multi-URL trend overlay
        tools.add_command(label="Multi-URL risk trend overlay...", command=self._open_multi_trend)
        # E4: standalone HTML diff viewer
        tools.add_command(label="Two-report HTML diff viewer...", command=self._open_diff_viewer)
        tools.add_command(label="Snapshot diff (same site, two scans)...",
                            command=self._open_snapshot_diff)
        # #41 — saved-sites credential vault
        tools.add_command(label="Saved sites (credential vault)...",
                            command=self._open_saved_sites)
        # #47 — per-check heatmap across recent snapshots of the current URL
        tools.add_command(label="Check-history heatmap (current URL)...",
                            command=self._open_check_heatmap)
        # E7: drill historical findings by OWASP/ATT&CK/CWE/D3FEND tag
        tools.add_command(label="Drill historical findings by tag...", command=self._open_drill_by_tag)
        # F5: drop-in marketplace browser
        tools.add_command(label="Drop-in marketplace...", command=self._open_marketplace)
        # Round-56: synthetic demo so users can see every feature working
        tools.add_command(label="Demo mode (synthetic scan)", command=self._run_demo)
        tools.add_separator()
        # C1 / C3 / C5: new tools-menu entries from the 24-feature round
        tools.add_command(label="Enable / disable checks...", command=self._open_disable_grid)
        tools.add_command(label="Search scan history...", command=self._open_history_search)
        tools.add_command(label="Show fix recommendations for last scan", command=self._open_recommendations)
        tools.add_separator()
        # Defender false-positive: one-click helper any time, not just first run.
        tools.add_command(label="Add Windows Defender exclusion...",
                          command=lambda: self._open_defender_dialog(is_first_run=False))
        tools.add_separator()
        # Round-62: new tools entries (graceful failure if module missing)
        tools.add_command(label="Vulnerability DB status / update...",
                          command=self._open_db_status)
        tools.add_command(label="Sites dashboard...",
                          command=self._open_sites_dashboard)
        tools.add_command(label="CVE alert subscriptions...",
                          command=self._open_cve_subscriptions)
        tools.add_command(label="Proxy settings...",
                          command=self._open_proxy_settings)
        tools.add_command(label="User mode (Beginner / Standard / Expert)...",
                          command=self._open_mode_picker)
        tools.add_command(label="Report a bug / send feedback...",
                          command=self._open_bug_report)
        tools.add_separator()
        # Round-65: opt-in features behind explicit settings panels
        tools.add_command(label="Advanced AI options...",
                          command=self._open_advanced_ai_options)
        tools.add_command(label="Usage analytics options...",
                          command=self._open_analytics_options)
        from . import i18n as _i18n
        menubar.add_cascade(label=_i18n.t("tools"), menu=tools)
        # Round-S: View menu (light theme / TTS / etc.)
        view_menu = tkinter.Menu(menubar, tearoff=False)
        self._tts_menu_var = BooleanVar(value=bool(getattr(self, "tts_enabled", False)))
        # O48 — language submenu inside View
        lang_menu = tkinter.Menu(view_menu, tearoff=False)
        for code in _i18n.available_locales():
            lang_menu.add_radiobutton(
                label=code.upper(),
                value=code,
                variable=getattr(self, "_locale_var", None) or self._init_locale_var(),
                command=lambda c=code: self._on_locale_change(c),
            )
        view_menu.add_cascade(label="Language", menu=lang_menu)
        view_menu.add_separator()
        view_menu.add_checkbutton(label="Read scan summary aloud (TTS)",
                                  variable=self._tts_menu_var,
                                  command=self._on_tts_toggle)
        menubar.add_cascade(label="View", menu=view_menu)
        help_menu = tkinter.Menu(menubar, tearoff=False)
        help_menu.add_command(label="Keyboard shortcuts", command=self._show_shortcuts)
        # E10 tutorial — always available via Help menu
        help_menu.add_command(label="Tutorial (guided tour)", command=self._open_tutorial)
        # O49: token-setup wizard — reachable any time, not just first launch
        help_menu.add_command(label="Setup wizard (API tokens)", command=self._open_onboarding_wizard)
        # Round-57: manual update check (always re-fetches, ignoring the 24h cache)
        help_menu.add_command(label="Check for updates now",
                              command=lambda: self._maybe_show_update_notice(force=True))
        help_menu.add_command(label="About Windows Defender warnings",
                              command=lambda: self._open_defender_dialog(is_first_run=False))
        help_menu.add_command(label=f"About {APP_NAME}", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)
        self.root.bind_all("<Control-t>", lambda _e: self._open_payload_tester())
        # More keyboard shortcuts: F5 = start scan, Esc = cancel, Ctrl+E/Ctrl+W = expand/collapse all,
        # Ctrl+L = focus URL field, Ctrl+H = open last HTML report, Ctrl+J = copy JSON
        self.root.bind_all("<F5>", lambda _e: self._on_scan_click())
        self.root.bind_all("<Escape>", lambda _e: self._on_cancel())
        self.root.bind_all("<Control-e>", lambda _e: self._expand_all() if hasattr(self, "_expand_all") else None)
        self.root.bind_all("<Control-w>", lambda _e: self._collapse_all() if hasattr(self, "_collapse_all") else None)
        self.root.bind_all("<Control-l>", lambda _e: self.url_entry.focus_set())
        self.root.bind_all("<Control-comma>", lambda _e: self._open_settings())
        self.root.bind_all("<Control-h>", lambda _e: self._open_html())
        self.root.bind_all("<Control-j>", lambda _e: self._copy_json())
        # Tab-cycle through findings (Ctrl+Down / Ctrl+Up)
        self.root.bind_all("<Control-Down>", lambda _e: self._cycle_finding(+1))
        self.root.bind_all("<Control-Up>", lambda _e: self._cycle_finding(-1))
        # #57: complete the keyboard set so the GUI is usable mouse-free.
        self.root.bind_all("<Control-o>", lambda _e: self._open_saved_report())
        self.root.bind_all("<Control-s>", lambda _e: self._save_profile_prompt())
        self.root.bind_all("<Control-Shift-E>", lambda _e: self._export_markdown())
        # #51: Ctrl+P toggles pause/resume during an active scan.
        self.root.bind_all("<Control-p>", lambda _e: self._on_pause())
        self.root.bind_all("<Control-d>", lambda _e: self._open_snapshot_diff())

        # --- Top bar: URL + scan + options ---
        top = ttk.Frame(self.root, padding=(16, 14, 16, 8))
        top.pack(side="top", fill="x")

        ttk.Label(top, text="URL").grid(row=0, column=0, sticky="w", padx=(0, 8))
        from . import history as _history
        recent = _history.recent_urls()
        self.url_entry = ttk.Combobox(top, textvariable=self.url_var, font=("Segoe UI", 11),
                                       values=recent if recent else ())
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        self.url_entry.bind("<Return>", lambda _e: self._on_scan_click())
        self._install_placeholder(self.url_entry, "https://example.com")
        self.url_entry.focus_set()
        self.diff_btn = ttk.Button(top, text="Diff w/ last", command=self._on_diff_last, state=DISABLED)
        self.diff_btn.grid(row=0, column=7, padx=(8, 0))
        _Tooltip(self.diff_btn, "Enabled after a scan if a previous report\nfor this URL exists in ~/.wpsecscan/reports/.")

        self.scan_btn = ttk.Button(top, text="Scan", style="Accent.TButton", command=self._on_scan_click)
        self.scan_btn.grid(row=0, column=2, padx=(0, 8))
        # #7: live scan-duration estimate, updates as toggles change
        self.eta_var = StringVar(value="")
        ttk.Label(top, textvariable=self.eta_var, foreground=MUTED).grid(row=0, column=8, padx=(8, 0), sticky="w")

        self.cancel_btn = ttk.Button(top, text="Cancel", command=self._on_cancel, state=DISABLED)
        self.cancel_btn.grid(row=0, column=3, padx=(0, 8))
        # #51: pause/resume — disabled until a scan starts. Same lifecycle as cancel.
        self.pause_btn = ttk.Button(top, text="Pause", command=self._on_pause, state=DISABLED)
        self.pause_btn.grid(row=0, column=4, padx=(0, 8))
        _Tooltip(self.pause_btn, "Pause the scan (Ctrl+P).\nThe currently-running check finishes, then the loop blocks until you Resume.")
        # #4: re-scan re-uses the last-scanned URL + current toggle state. Disabled until a scan completes.
        self.rescan_btn = ttk.Button(top, text="Re-scan", command=self._on_rescan, state=DISABLED)
        self.rescan_btn.grid(row=0, column=5, padx=(0, 8))
        _Tooltip(self.rescan_btn, "Re-run against the last URL using CURRENT toggles.\nTo repeat the same settings, save them via File → Profiles first.\nEnabled after a scan completes.")

        self.open_html_btn = ttk.Button(top, text="Open HTML", command=self._open_html, state=DISABLED)
        self.open_html_btn.grid(row=0, column=6, padx=(0, 8))
        _Tooltip(self.open_html_btn, "Open the saved HTML report in your browser.\nEnabled after a successful scan.")
        # #3: open the output directory in Explorer so users find their JSON/CSV/SARIF files.
        self.open_folder_btn = ttk.Button(top, text="Open folder", command=self._open_out_folder, state=DISABLED)
        self.open_folder_btn.grid(row=0, column=9, padx=(0, 8))
        _Tooltip(self.open_folder_btn, "Open the output folder in Explorer.\nEnabled after a successful scan.")

        self.copy_btn = ttk.Button(top, text="Copy JSON", command=self._copy_json, state=DISABLED)
        self.copy_btn.grid(row=0, column=10)
        _Tooltip(self.copy_btn, "Copy the full scan report (JSON) to clipboard.\nEnabled after a successful scan.")

        ttk.Checkbutton(
            top, text="Save HTML + JSON to disk", variable=self.save_reports_var
        ).grid(row=1, column=1, sticky="w", pady=(8, 0))

        ttk.Checkbutton(
            top,
            text="Aggressive mode (SQLi + XSS + SSRF + path-traversal + open-redirect + upload-endpoint probes)",
            variable=self.aggressive_var,
            command=self._on_aggressive_toggle,
        ).grid(row=2, column=1, sticky="w", pady=(2, 0))

        ttk.Checkbutton(
            top,
            text="Extract read-only proof for confirmed vulnerabilities (single-target, no writes)",
            variable=self.prove_var,
            command=self._on_prove_toggle,
        ).grid(row=2, column=2, columnspan=4, sticky="w", pady=(2, 0))

        dt_row = ttk.Frame(top)
        dt_row.grid(row=5, column=1, columnspan=4, sticky="w", pady=(2, 0))
        ttk.Checkbutton(
            dt_row,
            text="Deep throttle mapping — wrong logins for a synthetic user:",
            variable=self.deep_throttle_var,
            command=self._on_deep_throttle_toggle,
        ).pack(side="left")
        min_a, max_a, _, _ = self._DT_BOUNDS
        self._dt_attempts_spin = ttk.Spinbox(
            dt_row,
            from_=min_a, to=max_a, increment=10, width=5,
            textvariable=self.deep_throttle_attempts_var,
            command=self._refresh_deep_throttle_eta,
        )
        self._dt_attempts_spin.pack(side="left", padx=(6, 4))
        self.deep_throttle_attempts_var.trace_add("write", lambda *_: (self._refresh_deep_throttle_eta(), self._refresh_total_eta()))
        self.deep_throttle_pacing_var.trace_add("write", lambda *_: (self._refresh_deep_throttle_eta(), self._refresh_total_eta()))
        # #7: keep the total-ETA label fresh as ANY toggle changes
        for v in (self.aggressive_var, self.prove_var, self.deep_throttle_var,
                  self.auth_user_var, self.auth_pass_var):
            v.trace_add("write", lambda *_: self._refresh_total_eta())
        ttk.Label(dt_row, textvariable=self.deep_throttle_eta_var, foreground=MUTED).pack(side="left", padx=(4, 8))
        ttk.Button(dt_row, text="⚙ Settings", command=self._open_deep_throttle_settings, width=11).pack(side="left")
        self._refresh_deep_throttle_eta()
        self._refresh_total_eta()

        # Auth row — optional admin credentials for an authenticated scan
        auth_row = ttk.Frame(top)
        auth_row.grid(row=3, column=1, sticky="ew", pady=(6, 0))
        ttk.Label(auth_row, text="Admin (optional):", foreground=MUTED).pack(side="left", padx=(0, 6))
        ttk.Label(auth_row, text="user").pack(side="left")
        ttk.Entry(auth_row, textvariable=self.auth_user_var, width=18).pack(side="left", padx=(4, 8))
        ttk.Label(auth_row, text="password").pack(side="left")
        ttk.Entry(auth_row, textvariable=self.auth_pass_var, width=18, show="*").pack(side="left", padx=(4, 8))
        ttk.Label(auth_row, text="(scans wp-admin, role audit, Site Health)", foreground=MUTED).pack(side="left")

        # DB status + refresh
        db_row = ttk.Frame(top)
        db_row.grid(row=4, column=1, sticky="ew", pady=(6, 0))
        ttk.Label(db_row, textvariable=self.db_status_var, foreground=MUTED).pack(side="left")
        ttk.Button(db_row, text="Refresh vuln DB", command=self._on_refresh_db).pack(side="left", padx=(8, 0))

        top.columnconfigure(1, weight=1)

        # --- Status / progress strip ---
        strip = ttk.Frame(self.root, padding=(16, 4, 16, 8))
        strip.pack(side="top", fill="x")
        # Risk score badge (left-most, big)
        self.risk_var = StringVar(value="—")
        self.risk_label_widget = tkinter.Label(strip, textvariable=self.risk_var,
            font=("Segoe UI", 18, "bold"), bg=BG, fg=MUTED, padx=8)
        self.risk_label_widget.pack(side="left")
        ttk.Label(strip, textvariable=self.status_var, style="Muted.TLabel").pack(side="left", padx=(12, 0))
        self.progress = ttk.Progressbar(strip, mode="determinate", maximum=100, value=0, length=240)
        self.progress.pack(side="right")
        # #7: persistent toast — small green pill that fades after ~5s.
        self.toast_widget = tkinter.Label(strip, textvariable=self.toast_var,
                                          bg="#0c2a18", fg="#6cc474",
                                          font=("Segoe UI", 9, "bold"),
                                          padx=10, pady=2)
        # Don't pack until there's a message — pack/unpack in _toast()

        # --- Filter / search bar ---
        filt = ttk.Frame(self.root, padding=(16, 0, 16, 6))
        filt.pack(side="top", fill="x")
        ttk.Label(filt, text="Show:", foreground=MUTED).pack(side="left", padx=(0, 6))
        for label, var in (("critical", self.show_critical_var), ("high", self.show_high_var),
                           ("medium", self.show_medium_var), ("low", self.show_low_var),
                           ("info", self.show_info_var)):
            ttk.Checkbutton(filt, text=label, variable=var, command=self._apply_filter).pack(side="left", padx=(0, 8))
        ttk.Label(filt, text="  Search:", foreground=MUTED).pack(side="left", padx=(8, 4))
        sx = ttk.Entry(filt, textvariable=self.search_var, width=28)
        sx.pack(side="left")
        sx.bind("<KeyRelease>", lambda _e: self._apply_filter())
        # Tree control buttons
        ttk.Button(filt, text="Expand all", command=self._expand_all).pack(side="left", padx=(8, 0))
        ttk.Button(filt, text="Collapse all", command=self._collapse_all).pack(side="left", padx=(4, 0))
        self.sort_severity_var = BooleanVar(value=False)
        ttk.Checkbutton(filt, text="Sort by severity", variable=self.sort_severity_var,
                        command=self._on_sort_toggle).pack(side="left", padx=(8, 0))
        # #5: filter pills
        self.pill_only_new_var = BooleanVar(value=False)
        self.pill_only_confirmed_var = BooleanVar(value=False)
        # Default OFF: annotated findings stay visible until the user opts in to hiding them.
        self.pill_hide_annotated_var = BooleanVar(value=False)
        # C2: group by OWASP — when ON, the tree shows A01-A10 parents instead of check_id parents
        self.group_by_owasp_var = BooleanVar(value=False)
        ttk.Label(filt, text=" │ ", foreground=MUTED).pack(side="left")
        ttk.Checkbutton(filt, text="Only NEW", variable=self.pill_only_new_var,
                        command=self._apply_filter).pack(side="left")
        ttk.Checkbutton(filt, text="Only CONFIRMED", variable=self.pill_only_confirmed_var,
                        command=self._apply_filter).pack(side="left", padx=(4, 0))
        ttk.Checkbutton(filt, text="Hide annotated", variable=self.pill_hide_annotated_var,
                        command=self._apply_filter).pack(side="left", padx=(4, 0))
        # C2: group-by-OWASP toggle
        ttk.Label(filt, text=" │ ", foreground=MUTED).pack(side="left")
        ttk.Checkbutton(filt, text="Group by OWASP", variable=self.group_by_owasp_var,
                        command=self._on_group_by_owasp_toggle).pack(side="left", padx=(4, 0))
        # Export buttons on the right
        ttk.Button(filt, text="Export CSV", command=self._export_csv).pack(side="right", padx=(4, 0))
        ttk.Button(filt, text="Export SARIF", command=self._export_sarif).pack(side="right", padx=(4, 0))

        # --- Main split: tree on left, detail on right ---
        body = ttk.Frame(self.root, padding=(16, 4, 16, 4))
        body.pack(fill="both", expand=True)

        paned = ttk.Panedwindow(body, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # Left: tree of checks/findings
        left = ttk.Frame(paned, style="Panel.TFrame")
        paned.add(left, weight=2)

        self.tree = ttk.Treeview(left, columns=("severity",), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Check / Finding")
        self.tree.heading("severity", text="Severity")
        self.tree.column("#0", width=380, anchor="w")
        self.tree.column("severity", width=100, anchor="w")
        for sev, color in SEVERITY_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)
        self.tree.tag_configure("check",   foreground=FG, font=("Segoe UI", 10, "bold"))
        self.tree.tag_configure("ok",      foreground=MUTED)
        self.tree.tag_configure("err",     foreground="#ff5252")
        self.tree.tag_configure("running", foreground=ACCENT, font=("Segoe UI", 10, "bold"))
        tree_scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        # #43 — double-click a finding row opens its URL in the system browser.
        self.tree.bind("<Double-Button-1>", self._on_tree_double_click)
        # Right-click context menu (Windows uses Button-3)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

        self._ctx_menu = tkinter.Menu(self.root, tearoff=False)
        self._ctx_menu.add_command(label="Copy URL", command=self._ctx_copy_url)
        self._ctx_menu.add_command(label="Copy curl (replay)", command=self._ctx_copy_curl)
        self._ctx_menu.add_command(label="Open URL in browser", command=self._ctx_open_browser)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Copy finding (markdown)", command=self._ctx_copy_markdown)
        self._ctx_menu.add_separator()
        # #3: annotations
        self._ctx_menu.add_command(label="Mark as accepted risk...", command=lambda: self._annotate("accepted-risk"))
        self._ctx_menu.add_command(label="Mark as false positive...", command=lambda: self._annotate("false-positive"))
        self._ctx_menu.add_command(label="Clear annotation", command=lambda: self._annotate(""))
        # G1 / G2: assignee + comments
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Assign owner...", command=self._ctx_assign_owner)
        self._ctx_menu.add_command(label="Add / view comments...", command=self._ctx_comments)
        # E3: walk the exploit playbook step-by-step
        self._ctx_menu.add_command(label="Walk exploit playbook (E3)...", command=self._ctx_walk_playbook)
        # #15: per-finding quick actions
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Run nuclei tag for this check", command=self._ctx_run_nuclei)
        self._ctx_menu.add_command(label="Open in sqlmap (proven param)", command=self._ctx_open_sqlmap)
        # #52: per-check skip from the right-click menu
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Never run this check again",
                                      command=self._ctx_disable_check)

        # Right: notebook with "Finding detail" + "Activity feed" tabs
        right_outer = ttk.Frame(paned, style="Panel.TFrame")
        paned.add(right_outer, weight=3)

        import tkinter as tk
        self._right_notebook = ttk.Notebook(right_outer)
        self._right_notebook.pack(fill="both", expand=True)

        # Tab 1 — Finding detail (existing detail widget)
        right = ttk.Frame(self._right_notebook, style="Panel.TFrame")
        self._right_notebook.add(right, text="Finding detail")

        self.detail = tk.Text(
            right,
            wrap="word",
            bg=PANEL,
            fg=FG,
            insertbackground=FG,
            relief="flat",
            padx=14,
            pady=12,
            font=("Segoe UI", 10),
        )
        # Read-only by key-blocker (state=NORMAL keeps keyboard focus & Ctrl+C working)
        def _ro_keys(event):
            if event.state & 0x4 and event.keysym.lower() in ("c", "a"):
                return None  # let Ctrl+C / Ctrl+A through
            if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End",
                                "Page_Up", "Page_Down", "Tab",
                                "Shift_L", "Shift_R", "Control_L", "Control_R",
                                "Alt_L", "Alt_R"):
                return None
            return "break"
        self.detail.bind("<KeyPress>", _ro_keys)
        self.detail.bind("<<Paste>>", lambda _e: "break")
        self.detail.bind("<<Cut>>", lambda _e: "break")
        # Right-click menu on the detail pane: copy selection / remediation / full finding
        self._detail_menu = tk.Menu(self.root, tearoff=0)
        self._detail_menu.add_command(label="Copy selection", command=self._detail_copy_selection)
        self._detail_menu.add_command(label="Copy fix / remediation", command=self._detail_copy_remediation)
        self._detail_menu.add_command(label="Copy finding as markdown", command=self._detail_copy_finding_md)
        self.detail.bind("<Button-3>", lambda e: self._detail_menu.tk_popup(e.x_root, e.y_root))
        det_scroll = ttk.Scrollbar(right, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=det_scroll.set)
        self.detail.pack(side="left", fill="both", expand=True)
        det_scroll.pack(side="right", fill="y")

        for sev, color in SEVERITY_COLOR.items():
            self.detail.tag_configure(f"sev_{sev}", foreground=color, font=("Segoe UI", 11, "bold"))
        self.detail.tag_configure("h1", font=("Segoe UI", 13, "bold"), foreground=FG, spacing3=8)
        self.detail.tag_configure("h2", font=("Segoe UI", 10, "bold"), foreground=FG, spacing1=10, spacing3=4)
        self.detail.tag_configure("muted", foreground=MUTED)
        self.detail.tag_configure("mono", background=PANEL2, font=("Consolas", 10), lmargin1=8, lmargin2=8, spacing1=4, spacing3=4)
        self.detail.tag_configure("url", foreground=ACCENT, underline=True)
        # Exploit-playbook tool tags (colored chips per attacker tool)
        # #9: small OWASP/ATT&CK chips next to a finding's title
        self.detail.tag_configure("chip_owasp",  foreground="#f0a050", background="#2a1d10", font=("Segoe UI", 9, "bold"), spacing1=2)
        self.detail.tag_configure("chip_attack", foreground="#dca6e8", background="#1a0e1f", font=("Segoe UI", 9, "bold"), spacing1=2)
        # #13: exploit-confidence chips
        self.detail.tag_configure("conf_high", foreground="#79e0d0", background="#0c2a18", font=("Segoe UI", 9, "bold"), spacing1=2, spacing3=4)
        self.detail.tag_configure("conf_med",  foreground="#f0c674", background="#2a2410", font=("Segoe UI", 9, "bold"), spacing1=2, spacing3=4)
        self.detail.tag_configure("conf_low",  foreground="#8b949e", background="#1c1f24", font=("Segoe UI", 9, "bold"), spacing1=2, spacing3=4)
        self.detail.tag_configure("pb_header", foreground="#dca6e8", font=("Segoe UI", 11, "bold"), spacing1=12, spacing3=4)
        self.detail.tag_configure("pb_hau", foreground="#e6c7ee", lmargin1=8, lmargin2=8, spacing3=6)
        self.detail.tag_configure("pb_label", foreground=FG, font=("Segoe UI", 9, "bold"), spacing1=8, spacing3=2)
        self.detail.tag_configure("tool_sqlmap", foreground="#ff8a85", font=("Consolas", 10), background=PANEL2, lmargin1=8, lmargin2=8)
        self.detail.tag_configure("tool_msf", foreground="#c8a6f0", font=("Consolas", 10), background=PANEL2, lmargin1=8, lmargin2=8)
        self.detail.tag_configure("tool_curl", foreground="#79c0ff", font=("Consolas", 10), background=PANEL2, lmargin1=8, lmargin2=8)
        self.detail.tag_configure("tool_nuclei", foreground="#79e0d0", font=("Consolas", 10), background=PANEL2, lmargin1=8, lmargin2=8)
        self.detail.tag_configure("tool_wpscan", foreground="#a6b6f0", font=("Consolas", 10), background=PANEL2, lmargin1=8, lmargin2=8)
        self.detail.tag_configure("tool_ffuf", foreground="#f0c674", font=("Consolas", 10), background=PANEL2, lmargin1=8, lmargin2=8)
        self.detail.tag_configure("tool_ref", foreground=ACCENT, font=("Consolas", 9), lmargin1=8, lmargin2=8, underline=True)

        self._set_detail_placeholder()

        # Tab 2 — Activity feed (round-56)
        activity_tab = ttk.Frame(self._right_notebook, style="Panel.TFrame")
        self._right_notebook.add(activity_tab, text="Activity")
        self.activity_text = tk.Text(
            activity_tab, wrap="word", bg=PANEL, fg=FG, insertbackground=FG,
            relief="flat", padx=10, pady=10, font=("Consolas", 9),
        )
        act_scroll = ttk.Scrollbar(activity_tab, orient="vertical",
                                    command=self.activity_text.yview)
        self.activity_text.configure(yscrollcommand=act_scroll.set)
        self.activity_text.pack(side="left", fill="both", expand=True)
        act_scroll.pack(side="right", fill="y")
        # Category-badge tags — colors match console_live._CAT_BADGE
        self.activity_text.tag_configure("ts",         foreground=MUTED, font=("Consolas", 8))
        self.activity_text.tag_configure("threat_intel", foreground="#f0c674", font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("reporter",   foreground="#79c0ff", font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("integration",foreground="#dca6e8", font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("governance", foreground="#79e0d0", font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("meta",       foreground="#f0a050", font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("artifact",   foreground="#6cc474", font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("check",      foreground=FG, font=("Consolas", 9, "bold"))
        self.activity_text.tag_configure("msg",        foreground=FG)
        self.activity_text.insert("end", "(activity events will appear here as features fire)\n", "ts")
        self.activity_text.config(state="disabled")
        # Subscribe to the activity bus — routes events into the queue so
        # _drain_queue can append them on the Tk thread.
        try:
            from . import activity as _act
            def _on_activity(event: dict, _self=self) -> None:
                try:
                    _self._queue.put(("activity", event))
                except Exception:  # noqa: BLE001
                    pass
            self._activity_subscriber = _on_activity
            _act.subscribe(_on_activity)

            # Unsubscribe on window close so the activity bus doesn't keep a
            # reference to a destroyed Tk callback (which would TclError when
            # events fire post-shutdown).
            def _on_close():
                try:
                    _act.unsubscribe(self._activity_subscriber)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    self.root.destroy()
                except Exception:  # noqa: BLE001
                    pass
            self.root.protocol("WM_DELETE_WINDOW", _on_close)
        except Exception:  # noqa: BLE001
            pass

        # UX-036: chain first-run dialogs via <Destroy> instead of fixed
        # after() delays — keeps Defender → Tutorial → Wizard → Update
        # in strict order regardless of how long the user spends on each
        # popup.
        self._run_first_run_chain()
        # E9 voice readout — opt-in via preference; default off.
        self.tts_enabled = self._load_pref("tts_enabled", False)

        # #56: minimize-to-tray. start_tray() returns None when pystray /
        # Pillow aren't installed; the WM_DELETE handler falls through to
        # destroy() in that case.
        from . import tray as _tray
        _tray.start_tray(self)
        self.root.protocol("WM_DELETE_WINDOW",
                              lambda: _tray.hide_to_tray(self))

        # --- Bottom summary bar ---
        bottom = ttk.Frame(self.root, padding=(16, 6, 16, 12), style="Panel.TFrame")
        bottom.pack(side="bottom", fill="x")
        ttk.Label(bottom, textvariable=self.summary_var, style="Summary.TLabel").pack(side="left")

    # ---------- Helpers ----------

    def _set_detail_placeholder(self) -> None:
        """#1: first-run pane — five-step quick-start with feature links."""
        self.detail.delete("1.0", END)
        self.detail.insert(END, f"{APP_NAME}  ·  v{__version__}\n", "h1")
        self.detail.insert(
            END,
            "Defensive recon + vulnerability probing for WordPress sites you own.\n\n",
            "muted",
        )

        # Configure clickable-label tags for quick-start steps
        self.detail.tag_configure("qs_step", font=("Segoe UI", 10, "bold"), foreground=ACCENT, spacing1=8, spacing3=4)
        self.detail.tag_configure("qs_body", foreground=FG, lmargin1=22, lmargin2=22, spacing3=4)
        self.detail.tag_configure("qs_link", foreground=ACCENT, underline=True, lmargin1=22, lmargin2=22, spacing3=4)

        # Make the link tag clickable — clicking opens the matching feature
        def _bind_link(tag_name: str, callback) -> None:
            self.detail.tag_bind(tag_name, "<Button-1>", lambda _e: callback())
            self.detail.tag_bind(tag_name, "<Enter>", lambda _e: self.detail.config(cursor="hand2"))
            self.detail.tag_bind(tag_name, "<Leave>", lambda _e: self.detail.config(cursor=""))

        steps = [
            ("1. Paste a URL above and click Scan",
             "Run a passive scan in ~60s. The risk score (top-left) shows 0–100, color-coded."),
            ("2. Click a finding to see the exploit playbook",
             "Every finding includes concrete sqlmap / Metasploit / curl / nuclei commands\n"
             "with {target} already substituted."),
            ("3. Open the saved report",
             "Click 'Open HTML' for the full color-coded HTML report, or 'Open folder' to find\n"
             "the JSON / CSV / SARIF files."),
            ("4. Scan multiple sites at once",
             "Tools → Multi-target scan… paste a URL list, get one row per site with risk score\n"
             "and Δ vs last scan."),
            ("5. Save your settings as a profile",
             "File → Save current settings as profile… so you don't have to re-toggle Aggressive,\n"
             "Deep-throttle, Save reports, etc. every time."),
        ]
        for title, body in steps:
            self.detail.insert(END, title + "\n", "qs_step")
            self.detail.insert(END, body + "\n", "qs_body")

        # Discoverability links to power-user features
        self.detail.insert(END, "\nOther features worth knowing about:\n", "h2")
        feature_links = [
            ("→ Settings (Ctrl+,)  ·  webhook alerts, deep-throttle tuning", "qs_link_settings", self._open_settings),
            ("→ Tools → Schedule recurring scan  ·  Windows Task Scheduler integration", "qs_link_sched", self._open_schedule),
            ("→ Tools → Show risk trend for current URL  ·  score history sparkline", "qs_link_trend", self._open_trend),
            ("→ Tools → Payload Tester (Ctrl+T)  ·  send a single hand-tuned payload", "qs_link_pt", self._open_payload_tester),
            ("→ Right-click a finding  ·  copy as markdown / accept-risk / run nuclei", "qs_link_rc", lambda: None),
            ("→ Help → Keyboard shortcuts  ·  F5 scan, Esc cancel, Ctrl+F search, Ctrl+↑/↓ cycle", "qs_link_kb", self._show_shortcuts),
        ]
        for label, tag, cb in feature_links:
            self.detail.insert(END, label + "\n", tag)
            self.detail.tag_configure(tag, foreground=ACCENT, underline=True, lmargin1=8, lmargin2=8, spacing3=2)
            _bind_link(tag, cb)

        self.detail.insert(END, "\n", "muted")
        self.detail.insert(END,
            "Only scan sites you own or have written permission to test. "
            "No bulk online brute force, no auto-exploitation.\n",
            "muted")

    def _normalize_url(self, raw: str) -> str:
        t = raw.strip()
        if not t:
            return ""
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        return t

    def _install_placeholder(self, entry, text: str) -> None:
        """Light-gray placeholder text that vanishes on focus."""
        entry._placeholder = text  # type: ignore[attr-defined]
        entry._placeholder_active = True  # type: ignore[attr-defined]
        entry.configure(foreground=MUTED)
        entry.insert(0, text)

        def on_focus_in(_e):
            if getattr(entry, "_placeholder_active", False):
                entry.delete(0, END)
                entry.configure(foreground=FG)
                entry._placeholder_active = False  # type: ignore[attr-defined]

        def on_focus_out(_e):
            if not entry.get():
                entry.configure(foreground=MUTED)
                entry.insert(0, entry._placeholder)  # type: ignore[attr-defined]
                entry._placeholder_active = True  # type: ignore[attr-defined]

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

    # ---------- Scan lifecycle ----------

    def _on_scan_click(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return
        # Treat placeholder as empty
        raw = "" if getattr(self.url_entry, "_placeholder_active", False) else self.url_var.get()
        target = self._normalize_url(raw)
        if not target or urlparse(target).hostname is None:
            messagebox.showwarning(APP_NAME, "Please enter a valid URL (e.g. https://example.com).")
            return
        # Replace placeholder text with the normalized URL
        if getattr(self.url_entry, "_placeholder_active", False):
            self.url_entry.delete(0, END)
            self.url_entry.configure(foreground=FG)
            self.url_entry._placeholder_active = False  # type: ignore[attr-defined]
        self.url_var.set(target)
        self._cancel_requested = False
        self.cancel_btn.configure(state=NORMAL)
        # #51: reset pause state + enable the button at scan start.
        self._pause_requested = False
        self.pause_btn.configure(state=NORMAL, text="Pause")

        # Reset UI
        for iid in self.tree.get_children(""):
            self.tree.delete(iid)
        self._finding_for_iid.clear()
        self._check_rows.clear()
        self._set_detail_placeholder()
        self._current_report = None
        self._last_html_path = None
        self._last_json_path = None
        self.open_html_btn.configure(state=DISABLED)
        self.copy_btn.configure(state=DISABLED)
        self.open_folder_btn.configure(state=DISABLED)
        self.scan_btn.configure(state=DISABLED, text="Scanning...")
        self.progress.configure(value=0)
        import time as _time
        self._scan_start_t = _time.perf_counter()
        self.status_var.set(f"Connecting to {target}...")
        self.summary_var.set("")
        # Reset summary footer color
        try:
            ttk.Style().configure("Summary.TLabel", background=PANEL, foreground=FG, padding=8)
        except Exception:  # noqa: BLE001
            pass

        aggressive = self.aggressive_var.get()
        active_checks = [(cid, cname, fn) for cid, cname, fn, agg in ALL_CHECKS if (not agg) or aggressive]
        self._total_checks = len(active_checks)
        self._done_checks = 0
        # Pre-create rows for each check so user sees them tick off
        for cid, cname, _ in active_checks:
            iid = self.tree.insert("", "end", text=f"⏳  {cname}", values=("queued",), tags=("ok",))
            self._check_rows[cid] = iid

        self._scan_thread = threading.Thread(
            target=self._run_scan, args=(target, aggressive), daemon=True
        )
        self._scan_thread.start()

    def _run_scan(self, target: str, aggressive: bool) -> None:
        def progress_cb(event: str, check_id: str, check_name: str, result: CheckResult | None) -> None:
            self._queue.put(("progress", event, check_id, check_name, result))

        auth_user = self.auth_user_var.get().strip() or None
        auth_pass = self.auth_pass_var.get() or None
        prove = bool(self.prove_var.get() and aggressive)
        deep_throttle = bool(self.deep_throttle_var.get())
        try:
            dt_attempts = int(self.deep_throttle_attempts_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            dt_attempts = 120
        try:
            dt_pacing = float(self.deep_throttle_pacing_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            dt_pacing = 10.0
        # Pick up tokens saved by the onboarding wizard so a "Settings → Setup
        # wizard" flow actually enriches the next scan (previously the tokens
        # were saved but never read at scan time).
        from .gui_windows import _load_setup_tokens
        tokens = _load_setup_tokens()
        try:
            try:
                http_timeout = float(self.http_timeout_var.get())
                if not 5.0 <= http_timeout <= 120.0:
                    http_timeout = 15.0
            except (_tk_mod.TclError, TypeError, ValueError):
                http_timeout = 15.0
            report = asyncio.run(
                scan(
                    target,
                    timeout=http_timeout,
                    aggressive=aggressive,
                    prove=prove,
                    sequential=True,   # GUI: run one at a time so you can watch
                    auth_user=auth_user,
                    auth_pass=auth_pass,
                    deep_throttle=deep_throttle,
                    deep_throttle_attempts=dt_attempts,
                    deep_throttle_pacing_s=dt_pacing,
                    on_progress=progress_cb,
                    is_cancelled=lambda: self._cancel_requested,
                    is_paused=lambda: self._pause_requested,
                    wpscan_token=tokens.get("wpscan_token") or None,
                    hibp_token=tokens.get("hibp_token") or None,
                    abuseipdb_token=tokens.get("abuseipdb_token") or None,
                    vt_token=tokens.get("vt_token") or None,
                    github_search_token=tokens.get("github_search_token") or None,
                )
            )
            self._queue.put(("done", report))
        except Exception as e:  # noqa: BLE001
            self._queue.put(("error", f"{type(e).__name__}: {e}"))

    # ---------- Filter, search, exports, DB ----------

    def _apply_filter(self) -> None:
        # #11: remember the selected finding so we can restore it if it survives the filter
        prev_sel_iid = None
        sel = self.tree.selection()
        if sel:
            prev_sel_iid = sel[0]

        show = {
            "critical": self.show_critical_var.get(),
            "high":     self.show_high_var.get(),
            "medium":   self.show_medium_var.get(),
            "low":      self.show_low_var.get(),
            "info":     self.show_info_var.get(),
        }
        q = self.search_var.get().strip().lower()
        # #5: filter pill flags
        only_new = bool(getattr(self, "pill_only_new_var", None) and self.pill_only_new_var.get())
        only_confirmed = bool(getattr(self, "pill_only_confirmed_var", None) and self.pill_only_confirmed_var.get())
        hide_annotated = bool(getattr(self, "pill_hide_annotated_var", None) and self.pill_hide_annotated_var.get())

        new_set: set[str] = getattr(self, "_new_finding_titles", set())
        anns: dict = {}
        if self._current_report:
            from . import history as _h
            anns = _h.load_annotations().get(self._current_report.target, {})

        for parent_iid in self.tree.get_children(""):
            visible_children = 0
            check_id = next((cid for cid, i in self._check_rows.items() if i == parent_iid), None)
            for child_iid in self.tree.get_children(parent_iid):
                f = self._finding_for_iid.get(child_iid)
                if not f:
                    continue
                sev_ok = show.get(f.severity, True)
                # #44 — CVE search. Two paths:
                #   "cve:CVE-2024-..." → exact match against finding.extra.cve
                #   anything else      → existing title/evidence substring match,
                #                        PLUS the extra.cve field for free.
                if q:
                    extra_cve = ((f.extra or {}).get("cve") or "").lower()
                    if q.startswith("cve:"):
                        wanted = q[4:].strip()
                        q_ok = bool(wanted) and wanted == extra_cve
                    else:
                        q_ok = (
                            q in f.title.lower()
                            or q in (f.evidence or "").lower()
                            or q in extra_cve
                        )
                else:
                    q_ok = True
                new_ok = (f.title in new_set) if only_new else True
                conf_ok = f.title.startswith("[CONFIRMED]") if only_confirmed else True
                ann_ok = True
                if hide_annotated and check_id:
                    from . import history as _h
                    fp = _h.annotation_fingerprint(check_id, f.title)
                    if fp in anns:
                        ann_ok = False
                if sev_ok and q_ok and new_ok and conf_ok and ann_ok:
                    self.tree.reattach(child_iid, parent_iid, "end")
                    visible_children += 1
                else:
                    self.tree.detach(child_iid)
        # #11: restore the previous selection if it survived the filter
        if prev_sel_iid:
            try:
                if self.tree.exists(prev_sel_iid) and self.tree.parent(prev_sel_iid):
                    self.tree.selection_set(prev_sel_iid)
                    self.tree.see(prev_sel_iid)
            except tkinter.TclError:
                pass

    def _apply_filter_pills(self) -> None:
        """Alias kept for clarity; the main filter handles pills too."""
        self._apply_filter()

    def _export_csv(self) -> None:
        if not self._current_report:
            messagebox.showinfo(APP_NAME, "Run a scan first.")
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        csv_reporter.write(self._current_report, Path(path))
        self._toast(f"✓ CSV exported to {Path(path).name}")

    def _export_markdown(self) -> None:
        """#13: dump all findings as a single Markdown document — handy for tickets / Slack / wikis.
        Delegates to the shared reporters.markdown module so the CLI (`--md`) renders identically."""
        if not self._current_report:
            messagebox.showinfo(APP_NAME, "Run a scan first.")
            return
        from tkinter import filedialog
        from .reporters import markdown as _md
        path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
        if not path:
            return
        _md.write(self._current_report, Path(path))
        self._toast(f"✓ Markdown exported to {Path(path).name}")

    def _export_sarif(self) -> None:
        if not self._current_report:
            messagebox.showinfo(APP_NAME, "Run a scan first.")
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".sarif", filetypes=[("SARIF", "*.sarif"), ("JSON", "*.json")])
        if not path:
            return
        sarif_reporter.write(self._current_report, Path(path))
        # Use the toast system instead of status_var (which gets overwritten
        # on the next progress event) so the user actually sees confirmation.
        self._toast(f"✓ SARIF exported to {Path(path).name}")

    def _refresh_db_status(self) -> None:
        vulns, age, source = vulndb.load_local()
        if not vulns:
            self.db_status_var.set("DB: not loaded — click Refresh")
            return
        if source == "embedded":
            self.db_status_var.set(f"DB: embedded fallback ({len(vulns)} entries) — click Refresh for the full Wordfence DB")
        else:
            hrs = age // 3600 if age >= 0 else -1
            stale = " (stale)" if vulndb.is_stale(age) else ""
            self.db_status_var.set(f"DB: {len(vulns)} entries, {hrs}h old{stale}")

    def _on_refresh_db(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo(APP_NAME, "Wait for the current scan to finish, then refresh.")
            return
        self.db_status_var.set("DB: downloading Wordfence Intelligence (~10 MB)...")
        self.root.update_idletasks()

        def worker():
            try:
                n, path = vulndb.update_db(verbose=False)
                self._queue.put(("db_ok", n, str(path)))
            except Exception as e:  # noqa: BLE001
                self._queue.put(("db_err", f"{type(e).__name__}: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _drain_queue(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, event, check_id, check_name, result = msg
                    self._handle_progress(event, check_id, check_name, result)
                elif kind == "done":
                    _, report = msg
                    self._handle_done(report)
                elif kind == "error":
                    _, err = msg
                    self._handle_error(err)
                elif kind == "db_ok":
                    _, n, path = msg
                    self.db_status_var.set(f"DB refreshed: {n} entries cached at {path}")
                elif kind == "db_err":
                    _, err = msg
                    # The Wordfence Intelligence v3 endpoint requires an account
                    # as of 2026; the v2 endpoint returns 410 Gone. We continue
                    # to use the embedded 26-entry CVE DB, which still does
                    # useful matching — don't show this as a hard "failure".
                    self.db_status_var.set("DB: using embedded fallback (remote API gated)")
                    messagebox.showinfo(
                        APP_NAME,
                        "The public Wordfence Intelligence API now requires an account "
                        "(returned: " + err + ").\n\n"
                        "Your scans will continue to use the embedded CVE database "
                        "(26 well-known WordPress plugin CVEs). All other checks are unaffected.\n\n"
                        "To get full CVE coverage, you can:\n"
                        "  • Sign up at wordfence.com and host a paid feed yourself, or\n"
                        "  • Provide --wpscan-token <KEY> for per-plugin lookups via WPScan API"
                    )
                elif kind == "activity":
                    _, event = msg
                    self._append_activity(event)
        except queue.Empty:
            pass
        self.root.after(40, self._drain_queue)

    def _append_activity(self, event: dict) -> None:
        """Round-56: render an activity bus event into the Activity tab."""
        if not hasattr(self, "activity_text"):
            return
        try:
            import datetime as _dt
            ts = _dt.datetime.fromtimestamp(event.get("ts", 0)).strftime("%H:%M:%S")
            cat = event.get("category", "check")
            msg = event.get("message", "")
            self.activity_text.config(state="normal")
            # Cap to ~200 lines post-insert. tk.Text.delete("1.0", "K.0")
            # removes lines 1..K-1, so to drop down to 199 lines (then we add
            # one more) we delete to line `line_count - 199 + 1`.
            line_count = int(self.activity_text.index("end-1c").split(".")[0])
            if line_count > 200:
                self.activity_text.delete("1.0", f"{line_count - 199}.0")
            self.activity_text.insert("end", f"{ts}  ", "ts")
            badge = {
                "threat_intel": "intel",
                "reporter":     "rprt ",
                "integration":  "integ",
                "governance":   "gov  ",
                "meta":         "meta ",
                "artifact":     "art  ",
                "check":        "chk  ",
            }.get(cat, "?    ")
            self.activity_text.insert("end", f"[{badge}] ", cat)
            self.activity_text.insert("end", f"{msg}\n", "msg")
            self.activity_text.see("end")
            self.activity_text.config(state="disabled")
        except Exception:  # noqa: BLE001
            pass

    def _handle_progress(self, event: str, check_id: str, check_name: str, result: CheckResult | None) -> None:
        iid = self._check_rows.get(check_id)
        if event == "start":
            self.status_var.set(f"▶ Running: {check_name}...")
            if iid:
                self.tree.item(iid, text=f"⋯  {check_name}  (running...)", values=("running",), tags=("running",))
                self.tree.see(iid)
                self.tree.selection_set(iid)
        elif event == "step":
            # The scanner overloads `check_name` as the step label here. Show it
            # in the status bar so the user sees what's currently being probed.
            label = check_name
            self.status_var.set(f"▶ {label}")
            if iid:
                # Append a brief step hint to the row label so it's visible in the tree too
                current_cid = check_id
                cname_display = next((c[1] for c in ALL_CHECKS if c[0] == current_cid), current_cid)
                self.tree.item(iid, text=f"⋯  {cname_display}  ({label[:60]})")
            # #12: extract "attempt N/M" or "probe N/M" from the step text and
            # advance the progress bar fractionally within the current check's
            # slot so the bar doesn't appear frozen during long checks like
            # deep-throttle. Anchored to known progress phrases so false-positive
            # patterns like "rate 200/sec" don't shove the bar around.
            m = re.search(r"\b(?:attempt|probe|check|step|chunk)\s+(\d+)\s*/\s*(\d+)", label, re.IGNORECASE)
            if m and self._total_checks:
                try:
                    sub_done = int(m.group(1))
                    sub_total = int(m.group(2))
                    if sub_total > 0:
                        slot = 100.0 / self._total_checks
                        base = (self._done_checks / self._total_checks) * 100.0
                        within = (sub_done / sub_total) * slot
                        self.progress.configure(value=min(100.0, base + within))
                except (ValueError, ZeroDivisionError):
                    pass
        elif event == "done" and result is not None:
            self._done_checks += 1
            self.progress.configure(value=(self._done_checks / max(1, self._total_checks)) * 100)
            # C4: toast + audible beep when a critical finding lands mid-scan
            if not result.error:
                for f in result.findings:
                    if f.severity == "critical":
                        self._notify_critical_mid_scan(check_name, f.title)
                        break  # one notification per check is enough
            if iid:
                worst_sev = self._worst(result)
                badge = "✗" if result.error else "✓"
                # Build a label showing the finding count, with non-info counts highlighted
                non_info = sum(1 for f in result.findings if f.severity != "info")
                if result.error:
                    count_label = ""
                elif non_info:
                    count_label = f"  [{non_info} of {len(result.findings)} non-info]"
                elif result.findings:
                    count_label = f"  [{len(result.findings)} info]"
                else:
                    count_label = ""
                # Elapsed-time hint in the status bar
                import time as _time
                elapsed = _time.perf_counter() - getattr(self, "_scan_start_t", _time.perf_counter())
                self.status_var.set(f"{self._done_checks}/{self._total_checks} checks · {elapsed:.0f}s elapsed")
                self.tree.item(
                    iid,
                    text=f"{badge}  {check_name}{count_label}  ({result.duration_ms} ms)",
                    values=(worst_sev or "—",),
                    tags=("err" if result.error else "check",),
                )
                if result.error:
                    self.tree.insert(iid, "end", text=result.error, values=("error",), tags=("err",))
                    self.tree.item(iid, open=True)
                else:
                    sev_for_open = worst_sev in ("critical", "high", "medium")
                    for f in result.findings:
                        child = self.tree.insert(
                            iid, "end",
                            text=f.title,
                            values=(f.severity.upper(),),
                            tags=(f.severity,),
                        )
                        self._finding_for_iid[child] = f
                    if sev_for_open:
                        self.tree.item(iid, open=True)
                        # Auto-show the first interesting finding in the detail pane
                        children = self.tree.get_children(iid)
                        if children:
                            top_finding = self._finding_for_iid.get(children[0])
                            if top_finding:
                                self._show_finding(top_finding)
                # Live summary update
                self._refresh_summary_live()

    def _refresh_summary_live(self) -> None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for iid in self.tree.get_children(""):
            for child in self.tree.get_children(iid):
                f = self._finding_for_iid.get(child)
                if f:
                    counts[f.severity] = counts.get(f.severity, 0) + 1
        self.summary_var.set(
            f"  {counts['critical']} critical · {counts['high']} high · "
            f"{counts['medium']} medium · {counts['low']} low · {counts['info']} info  "
            f"({self._done_checks}/{self._total_checks} checks)"
        )

    def _refresh_total_eta(self) -> None:
        """#7: update the small inline 'ETA ~24 min' next to the Scan button."""
        from .eta import estimate_scan_seconds, format_eta
        try:
            a = int(self.deep_throttle_attempts_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            a = 120
        try:
            p = float(self.deep_throttle_pacing_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            p = 10.0
        secs = estimate_scan_seconds(
            aggressive=bool(self.aggressive_var.get()),
            prove=bool(self.prove_var.get()),
            deep_throttle=bool(self.deep_throttle_var.get()),
            deep_throttle_attempts=a,
            deep_throttle_pacing_s=p,
            authenticated=bool(self.auth_user_var.get().strip() and self.auth_pass_var.get()),
        )
        self.eta_var.set(f"ETA ~{format_eta(secs)}")

    def _refresh_deep_throttle_eta(self) -> None:
        """Update the inline 'estimated 20 min' label based on current spinner values."""
        min_a, max_a, min_p, max_p = self._DT_BOUNDS
        try:
            a = int(self.deep_throttle_attempts_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            a = 0
        try:
            p = float(self.deep_throttle_pacing_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            p = 0.0
        a = max(min_a, min(max_a, a)) if a else min_a
        p = max(min_p, min(max_p, p)) if p else min_p
        eta_min = (a * p) / 60.0
        if eta_min < 1:
            label = f"≈ {a * p:.0f}s · {a}×{p:.0f}s"
        else:
            label = f"≈ {eta_min:.0f} min · {a}×{p:.0f}s"
        self.deep_throttle_eta_var.set(label)

    def _open_deep_throttle_settings(self) -> None:
        """Non-modal settings window for deep-throttle pacing (and attempts mirror).

        Singleton: clicking the button while the window is already open just
        raises the existing one. Non-modal so the user can keep clicking Scan
        / Cancel on the main window while the settings dialog is up.
        """
        existing = getattr(self, "_dt_settings_win", None)
        if existing is not None and existing.winfo_exists():
            existing.deiconify()
            existing.lift()
            existing.focus_force()
            return
        min_a, max_a, min_p, max_p = self._DT_BOUNDS
        win = _tk_mod.Toplevel(self.root)
        self._dt_settings_win = win
        win.title("Deep throttle settings")
        win.configure(bg=BG)
        win.transient(self.root)
        win.resizable(False, False)
        # Clear the singleton reference when the window is closed.
        win.bind("<Destroy>", lambda _e, w=win: self._on_dt_settings_destroyed(w))

        body = ttk.Frame(win, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Tune the deep-throttle mapper", font=("Segoe UI", 11, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        ttk.Label(body, text="Wrong-login attempts:").grid(row=1, column=0, sticky="w", padx=(0, 8))
        ttk.Spinbox(body, from_=min_a, to=max_a, increment=10, width=7,
                    textvariable=self.deep_throttle_attempts_var).grid(row=1, column=1, sticky="w")
        ttk.Label(body, text=f"({min_a}–{max_a})", foreground=MUTED).grid(row=1, column=2, sticky="w", padx=(6, 0))

        ttk.Label(body, text="Pacing between attempts (s):").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
        ttk.Spinbox(body, from_=min_p, to=max_p, increment=1.0, width=7, format="%.1f",
                    textvariable=self.deep_throttle_pacing_var).grid(row=2, column=1, sticky="w", pady=(8, 0))
        ttk.Label(body, text=f"({min_p:.0f}–{max_p:.0f})", foreground=MUTED).grid(row=2, column=2, sticky="w", padx=(6, 0), pady=(8, 0))

        eta_lbl = ttk.Label(body, textvariable=self.deep_throttle_eta_var, foreground=MUTED)
        eta_lbl.grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 4))

        warn = ttk.Label(
            body,
            text=(
                "Pacing below 5s tends to trip network-layer fail2ban before HTTP-layer\n"
                "throttling shows in the response. Above ~30s is rarely needed."
            ),
            foreground=MUTED,
            justify="left",
        )
        warn.grid(row=4, column=0, columnspan=3, sticky="w", pady=(4, 10))

        btns = ttk.Frame(body)
        btns.grid(row=5, column=0, columnspan=3, sticky="e", pady=(6, 0))
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")

        win.update_idletasks()
        # Centre on parent
        x = self.root.winfo_rootx() + (self.root.winfo_width() // 2) - (win.winfo_width() // 2)
        y = self.root.winfo_rooty() + 120
        win.geometry(f"+{x}+{y}")
        # Intentionally NOT calling grab_set() — this is a tuning dialog,
        # the user should be able to keep using the main window while it's open.

    def _on_dt_settings_destroyed(self, win) -> None:
        """Drop the singleton reference once Tk fires <Destroy> on the window."""
        if getattr(self, "_dt_settings_win", None) is win:
            self._dt_settings_win = None

    def _on_deep_throttle_toggle(self) -> None:
        if not self.deep_throttle_var.get():
            return
        try:
            attempts = int(self.deep_throttle_attempts_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            attempts = 120
        try:
            pacing = float(self.deep_throttle_pacing_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            pacing = 10.0
        est_min = (attempts * pacing) / 60.0
        ok = messagebox.askyesno(
            "Deep throttle mapping",
            f"This sends {attempts} deliberately-wrong logins for a synthetic non-existent user "
            f"(one every {pacing:.0f} seconds, ~{est_min:.0f} minutes total). The password is a fixed constant — "
            "we never vary it and never try real credentials.\n\n"
            "The check maps your login defense and reports:\n"
            "  • the exact attempt # at which throttling kicks in, or\n"
            f"  • that no HTTP-layer throttle was hit in {attempts} attempts (run hashcat against\n"
            "    a hash dump for the real password-strength audit)\n\n"
            "Note: this WILL show up in server logs as failed-login attempts for the\n"
            "canary username, and may trip network-layer defenses (fail2ban, hosting\n"
            "abuse detection) without showing it in the HTTP response.\n\n"
            "Proceed?",
            icon="warning",
        )
        if not ok:
            self.deep_throttle_var.set(False)

    def _on_prove_toggle(self) -> None:
        if not self.prove_var.get():
            return
        if not self.aggressive_var.get():
            messagebox.showinfo(
                APP_NAME,
                "Proof mode needs Aggressive mode on — it can only act on findings that the aggressive checks confirmed.\n\n"
                "Enable Aggressive mode first.",
            )
            self.prove_var.set(False)
            return
        ok = messagebox.askyesno(
            "Read-only proof extraction — sites you own only",
            "Proof mode will, for each confirmed aggressive finding, send ONE extra read-only request to extract evidence:\n\n"
            "  • SQLi → SELECT @@version (no table dumps, no PII)\n"
            "  • Path traversal → read first 200 bytes of wp-config.php (redacted)\n"
            "  • SSRF → probe http://127.0.0.1:80/\n"
            "  • Reflected XSS → re-fetch to confirm persistence\n\n"
            "These are read-only and never modify the target. They will, however:\n"
            "  • Show up in server logs as injection payloads\n"
            "  • Trip WAFs (Cloudflare, Wordfence)\n"
            "  • Possibly flag your scanning IP\n\n"
            "Proceed?",
            icon="warning",
        )
        if not ok:
            self.prove_var.set(False)

    def _on_aggressive_toggle(self) -> None:
        if not self.aggressive_var.get():
            return
        proceed = messagebox.askyesno(
            "Aggressive mode — sites you own only",
            "Aggressive mode will send active payloads to the target:\n\n"
            "  • SQL injection probes (read-only, includes time-based SLEEP(3) tests)\n"
            "  • Reflected XSS probes (benign marker payloads)\n"
            "  • Open-redirect tests\n"
            "  • Offline plugin-CVE matching against an embedded database\n\n"
            "These will:\n"
            "  • Trip WAFs (Cloudflare, Wordfence) and show up in server logs\n"
            "  • Briefly slow the site during time-based SQLi tests\n"
            "  • Possibly flag your scanning IP\n\n"
            "Only run on sites you own or have written permission to test.\n\n"
            "Proceed?",
            icon="warning",
        )
        if not proceed:
            self.aggressive_var.set(False)

    def _worst(self, result: CheckResult) -> str | None:
        # SEVERITY_ORDER is descending: lower index = more severe.
        # We want the finding with the LOWEST index.
        best_idx = len(SEVERITY_ORDER)  # higher than any real severity
        best_name: str | None = None
        for f in result.findings:
            try:
                idx = SEVERITY_ORDER.index(f.severity)
            except ValueError:
                continue
            if idx < best_idx:
                best_idx = idx
                best_name = f.severity
        return best_name

    def _handle_done(self, report: ScanReport) -> None:
        self._current_report = report
        s = report.summary
        cancelled = self._cancel_requested
        prefix = "Cancelled — " if cancelled else "Done — "
        # E9: voice readout of the summary if enabled.
        try:
            self._speak(
                f"Scan complete. Risk score {report.risk_score} of 100. "
                f"{s.get('critical', 0)} critical, {s.get('high', 0)} high, "
                f"{s.get('medium', 0)} medium findings."
            )
        except Exception:  # noqa: BLE001
            pass
        # Risk score badge
        from .risk import risk_tier, risk_label, risk_grade
        from . import history as _history
        score = report.risk_score
        tier = risk_tier(score)
        tier_fg = {"green": "#6cc474", "yellow": "#f0c674",
                   "orange": "#f0a050", "red": "#ff5252"}[tier]
        self.risk_var.set(f"{score}/100  {risk_grade(score)}")
        self.risk_label_widget.configure(fg=tier_fg)
        self.summary_var.set(
            f"{prefix}{s['critical']} critical · {s['high']} high · {s['medium']} medium · "
            f"{s['low']} low · {s['info']} info  •  risk {score}/100 ({risk_label(score)})  •  {report.duration_ms} ms"
        )
        # Persist URL to history + save snapshot for diff-with-last
        # #5: also compute the set of NEW finding titles (vs the prior snapshot) for the filter pill
        self._new_finding_titles = set()
        try:
            prior_path = _history.previous_report_path(report.target)
            if prior_path and prior_path.exists():
                import json as _json
                prior = _json.loads(prior_path.read_text(encoding="utf-8"))
                prior_titles = {f["title"] for r in prior.get("results", []) for f in r.get("findings", [])}
                self._new_finding_titles = {f.title for f in report.all_findings if f.title not in prior_titles}
        except (OSError, Exception):  # noqa: BLE001
            pass
        try:
            _history.push_url(report.target)
            self.url_entry.configure(values=_history.recent_urls())
            from .reporters import json_out as _json_reporter
            _history.save_report_snapshot(report.target, _json_reporter.render(report))
            self.diff_btn.configure(state=NORMAL)
        except Exception:  # noqa: BLE001
            pass
        # Refresh annotation suffixes on rows
        try:
            self._refresh_annotation_visuals()
        except Exception:  # noqa: BLE001
            pass
        # #12: webhook notify if configured + threshold met. Background-threaded
        # so an 8-second hang on the webhook doesn't freeze the GUI.
        # Dedupe: skip if we already fired for this exact (target, scanned_at).
        try:
            url = (self.webhook_url_var.get() or "").strip()
            fp = (report.target, report.scanned_at)
            already = getattr(self, "_last_webhook_fp", None)
            if url and fp != already:
                self._last_webhook_fp = fp
                from . import notify as _n
                def _wb_done(ok, msg, _self=self):
                    if ok:
                        _self.root.after(0, lambda: _self.status_var.set(_self.status_var.get() + " · webhook sent"))
                _n.notify_async(report, url, threshold=self.webhook_threshold_var.get() or "high", on_done=_wb_done)
        except Exception:  # noqa: BLE001
            pass
        # D2: GitHub Issues auto-create — opt-in, background-threaded.
        try:
            if self.github_enabled_var.get():
                repo = (self.github_repo_var.get() or "").strip()
                token = (self.github_token_var.get() or "").strip()
                threshold = self.github_threshold_var.get() or "high"
                if repo and token:
                    from .integrations import github_issues as _gh
                    import threading as _t
                    def _gh_worker(report=report, repo=repo, token=token, threshold=threshold, _self=self):
                        summary = _gh.create_issues_for_report(report, repo, token, threshold=threshold)
                        msg = (f"✓ {summary['ok']} GitHub issue(s) created"
                               + (f", {summary['fail']} failed" if summary['fail'] else ""))
                        _self.root.after(0, lambda: _self._toast(msg, duration_ms=8000))
                    _t.Thread(target=_gh_worker, daemon=True, name="wpsec-gh-issues").start()
        except Exception:  # noqa: BLE001
            pass
        worst = report.worst_severity()
        worst_color = SEVERITY_COLOR.get(worst or "", FG)
        try:
            ttk.Style().configure("Summary.TLabel", background=PANEL, foreground=worst_color, padding=8)
        except Exception:  # noqa: BLE001
            pass
        self.status_var.set(
            f"{'Scan cancelled' if cancelled else 'Scan complete'} for {report.target}"
        )
        # #45 — scan-completion notification. System toast (Windows) /
        # libnotify (Linux) / NSUserNotificationCenter (macOS) when the
        # main window is minimized OR has lost focus. Beeps once on
        # Windows so the user knows the long-running scan finished.
        if not cancelled:
            try:
                self._notify_scan_complete(report)
            except Exception:  # noqa: BLE001 — never let notifications break the scan
                pass
        self.progress.configure(value=100)
        self.scan_btn.configure(state=NORMAL, text="Scan")
        self.cancel_btn.configure(state=DISABLED)
        self.pause_btn.configure(state=DISABLED, text="Pause")
        self._pause_requested = False
        self.copy_btn.configure(state=NORMAL)
        # #3 / #4: enable open-folder + re-scan once we have a completed report
        self.open_folder_btn.configure(state=NORMAL)
        self.rescan_btn.configure(state=NORMAL)
        self._last_scanned_url = report.target
        self._cancel_requested = False

        # Auto-jump to the worst finding so the user sees the most important issue first
        self._focus_worst_finding()

        if self.save_reports_var.get():
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            stem = f"wpsecscan-{_safe_host(report.target)}-{ts}"
            out_dir = Path.cwd() / "wpsecscan-reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            html_path = out_dir / f"{stem}.html"
            json_path = out_dir / f"{stem}.json"
            html_reporter.write(report, html_path)
            json_reporter.write(report, json_path)
            self._last_html_path = html_path
            self._last_json_path = json_path
            self.open_html_btn.configure(state=NORMAL)
            self.status_var.set(f"Scan complete · reports saved to {out_dir}")

    def _handle_error(self, err: str) -> None:
        self.scan_btn.configure(state=NORMAL, text="Scan")
        self.cancel_btn.configure(state=DISABLED)
        self.pause_btn.configure(state=DISABLED, text="Pause")
        self._pause_requested = False
        self.status_var.set(f"Error: {err}")
        self._cancel_requested = False
        # Reset stale risk badge so a failed scan doesn't display the prior scan's score.
        self.risk_var.set("—")
        self.risk_label_widget.configure(fg=MUTED)
        # #2: convert opaque errors into actionable guidance.
        suggestion = _suggest_for_error(err)
        if suggestion:
            messagebox.showerror(APP_NAME, f"Scan failed:\n\n{err}\n\n— Suggested next step —\n{suggestion}")
        else:
            messagebox.showerror(APP_NAME, f"Scan failed:\n\n{err}")

    # ---------- Finding selection ----------

    def _on_select(self, _event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        finding = self._finding_for_iid.get(iid)
        if finding is None:
            # A check node was selected — show its summary instead
            self._show_check_summary(iid)
            return
        self._show_finding(finding)

    def _show_check_summary(self, iid: str) -> None:
        if not self._current_report:
            return
        # Find which check this iid corresponds to
        check_id = next((cid for cid, i in self._check_rows.items() if i == iid), None)
        if not check_id:
            return
        result = next((r for r in self._current_report.results if r.check_id == check_id), None)
        if not result:
            return
        self.detail.delete("1.0", END)
        self.detail.insert(END, result.check_name + "\n", "h1")
        self.detail.insert(END, f"{len(result.findings)} finding(s) · {result.duration_ms} ms\n\n", "muted")
        if result.error:
            self.detail.insert(END, "Error: " + result.error, ("sev_high",))
        else:
            for f in result.findings:
                self.detail.insert(END, f.severity.upper() + "  ", f"sev_{f.severity}")
                self.detail.insert(END, f.title + "\n", "h2")

    def _show_finding(self, finding, check_id: str | None = None) -> None:  # noqa: ANN001
        self._detail_finding = finding  # stash for right-click "copy remediation"
        self.detail.delete("1.0", END)
        self.detail.insert(END, finding.severity.upper() + "  ", f"sev_{finding.severity}")
        self.detail.insert(END, finding.title + "\n", "h1")
        # #13: exploit-confidence chip after the title
        try:
            from . import confidence as _conf
            waf_detected = bool(self._current_report and any(
                ("WAF" in (x.title or "") or "CDN detected" in (x.title or ""))
                for res in self._current_report.results if res.check_id == "waf"
                for x in res.findings
            ))
            level = _conf.compute_confidence(finding, check_id or "", waf_detected=waf_detected)
            chip_tag = {"high": "conf_high", "medium": "conf_med", "low": "conf_low"}[level]
            self.detail.insert(END, f" {_conf.chip(level)} \n", chip_tag)
        except Exception:  # noqa: BLE001
            pass
        if finding.url:
            self.detail.insert(END, finding.url + "\n", "url")
        if finding.evidence:
            self.detail.insert(END, "\nEvidence\n", "h2")
            self.detail.insert(END, finding.evidence + "\n", "mono")
        if finding.remediation:
            self.detail.insert(END, "\nRemediation\n", "h2")
            self.detail.insert(END, finding.remediation + "\n")
        # Resolve check_id from the currently-selected tree row if caller didn't pass one
        if check_id is None:
            sel = self.tree.selection()
            if sel:
                parent_iid = self.tree.parent(sel[0]) or sel[0]
                check_id = next((cid for cid, i in self._check_rows.items() if i == parent_iid), None)
        if check_id:
            from . import tags as _ctags
            tg = _ctags.get_tags(check_id)
            if tg:
                self.detail.insert(END, "\n")
                if tg.get("owasp"):
                    self.detail.insert(END, f" {tg['owasp']} ", "chip_owasp")
                    self.detail.insert(END, f"  {tg.get('owasp_label','')}\n", "muted")
                if tg.get("attack"):
                    self.detail.insert(END, f" {tg['attack']} ", "chip_attack")
                    self.detail.insert(END, f"  {tg.get('attack_label','')}\n", "muted")
        if check_id and self._current_report:
            self._append_playbook(check_id)

    def _append_playbook(self, check_id: str) -> None:
        """Render the exploit playbook for `check_id` at the end of the detail pane."""
        from . import playbook as _pb
        raw = _pb.get_playbook(check_id)
        if not raw:
            return
        subst = _pb.substitute(raw, self._current_report.target)
        buckets = _pb.ordered_buckets(subst)
        if not buckets:
            return
        self.detail.insert(END, "\nHow an attacker exploits this\n", "pb_header")
        for field, label, content in buckets:
            if field == "how_an_attacker_uses_this":
                self.detail.insert(END, content + "\n", "pb_hau")
                continue
            tag = {
                "sqlmap": "tool_sqlmap",
                "metasploit": "tool_msf",
                "manual_curl_pocs": "tool_curl",
                "nuclei": "tool_nuclei",
                "wpscan": "tool_wpscan",
                "ffuf_gobuster": "tool_ffuf",
                "references": "tool_ref",
            }.get(field, "mono")
            self.detail.insert(END, label + "\n", "pb_label")
            for line in content:
                self.detail.insert(END, line + "\n", tag)

    # ---------- Buttons ----------

    def _open_html(self) -> None:
        if self._last_html_path and self._last_html_path.exists():
            webbrowser.open(self._last_html_path.as_uri())

    def _open_out_folder(self) -> None:
        """#3: open the output folder in Windows Explorer (or system file manager)."""
        target = None
        for cand in (self._last_html_path, self._last_json_path):
            if cand and cand.exists():
                target = cand.parent
                break
        if target is None:
            target = Path.home() / ".wpsecscan" / "reports"
            target.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(target))  # noqa: S606 — opens in OS file manager
        except Exception as e:  # noqa: BLE001
            messagebox.showinfo(APP_NAME, f"Folder: {target}\n\n(Couldn't auto-open: {e})")

    def _notify_critical_mid_scan(self, check_name: str, finding_title: str) -> None:
        """C4: Windows toast + audible beep when a critical finding lands mid-scan.

        Best-effort: tries Windows 10 toast via PowerShell BurntToast; falls back
        to winsound.MessageBeep + a longer-duration in-app toast. Never blocks the
        scan thread."""
        msg = f"CRITICAL: {finding_title[:80]}"
        # Always show in-app toast (longer duration than usual)
        try:
            self._toast(f"⚠ {msg}", duration_ms=15000)
        except Exception:  # noqa: BLE001
            pass
        # System sound
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:  # noqa: BLE001
            pass
        # Windows native toast (background — never block GUI)
        def _toast_worker():
            try:
                import base64
                import subprocess
                # C5 (v2.7.2) — base64-EncodedCommand path so a finding
                # title containing single-quote / double-quote / newline
                # can't break out of the PS literal and inject commands.
                # The PS script itself uses single-quoted string literals
                # (which can't be escaped from); we double up any single
                # quotes inside the user-controlled strings.
                def _ps_lit(s: str) -> str:
                    # In PS single-quoted strings, '' is the only escape.
                    return s.replace("'", "''")
                body = f"{_ps_lit(check_name)}: {_ps_lit(finding_title[:60])}"
                script = (
                    "[void][Windows.UI.Notifications.ToastNotificationManager,"
                    "Windows.UI.Notifications,ContentType=WindowsRuntime];"
                    "$xml=[Windows.UI.Notifications.ToastNotificationManager]::"
                    "GetTemplateContent(0);"
                    "$xml.GetElementsByTagName('text')[0]."
                    "AppendChild($xml.CreateTextNode('WPSecScan critical finding')) "
                    "| Out-Null;"
                    f"$xml.GetElementsByTagName('text')[1]."
                    f"AppendChild($xml.CreateTextNode('{body}')) | Out-Null;"
                    "$toast=[Windows.UI.Notifications.ToastNotification]::new($xml);"
                    "[Windows.UI.Notifications.ToastNotificationManager]::"
                    "CreateToastNotifier('WPSecScan').Show($toast)"
                )
                encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-WindowStyle", "Hidden",
                     "-EncodedCommand", encoded],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            except Exception:  # noqa: BLE001
                pass
        import threading
        threading.Thread(target=_toast_worker, daemon=True).start()

    def _toast(self, msg: str, duration_ms: int = 5000) -> None:
        """#7: pop a small green pill that lingers ~5s instead of being overwritten
        in the status bar after 40 ms.

        Packed on the LEFT (after the status label) so it doesn't fight the
        progress bar for right-side space.
        """
        try:
            if self._toast_after_id:
                self.root.after_cancel(self._toast_after_id)
        except Exception:  # noqa: BLE001
            pass
        self.toast_var.set(msg)
        try:
            self.toast_widget.pack(side="left", padx=(12, 0))
        except tkinter.TclError:
            pass

        def _clear():
            # Defend against the case where the GUI is shutting down while a
            # toast clear is still pending — touching destroyed widgets raises TclError.
            try:
                self.toast_var.set("")
                self.toast_widget.pack_forget()
            except (tkinter.TclError, AttributeError):
                pass
            self._toast_after_id = None
        self._toast_after_id = self.root.after(duration_ms, _clear)

    def _on_rescan(self) -> None:
        """#4: re-run against the previous URL.

        Uses CURRENT toggle state (not the last scan's toggles) — common workflow
        is "passive scan → see findings → re-scan with --aggressive on". For
        repeatable runs with the same settings, use File → Save profile.
        """
        last = getattr(self, "_last_scanned_url", None)
        if not last:
            return
        self.url_var.set(last)
        self._on_scan_click()

    def _copy_json(self) -> None:
        if not self._current_report:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(json_reporter.render(self._current_report))
        self._toast("✓ JSON copied to clipboard")

    def _cycle_finding(self, direction: int) -> None:
        """Ctrl+Down/Up cycles through visible findings across all check parents."""
        # Collect all finding child iids (in tree order)
        all_findings: list[str] = []
        for parent_iid in self.tree.get_children(""):
            for child_iid in self.tree.get_children(parent_iid):
                if child_iid in self._finding_for_iid:
                    all_findings.append(child_iid)
        if not all_findings:
            return
        sel = self.tree.selection()
        cur = sel[0] if sel else None
        if cur not in all_findings:
            target_idx = 0 if direction > 0 else len(all_findings) - 1
        else:
            idx = all_findings.index(cur)
            target_idx = (idx + direction) % len(all_findings)
        target = all_findings[target_idx]
        parent = self.tree.parent(target)
        if parent:
            self.tree.item(parent, open=True)
        self.tree.selection_set(target)
        self.tree.see(target)
        f = self._finding_for_iid.get(target)
        if f:
            self._show_finding(f)

    def _focus_worst_finding(self) -> None:
        """Select and show the highest-severity finding across all checks."""
        best_iid: str | None = None
        best_rank = len(SEVERITY_ORDER)  # lower is worse in SEVERITY_ORDER
        for child_iid, finding in self._finding_for_iid.items():
            try:
                rank = SEVERITY_ORDER.index(finding.severity)
            except ValueError:
                continue
            if finding.severity == "info":
                continue
            if rank < best_rank:
                best_rank = rank
                best_iid = child_iid
        if best_iid:
            parent = self.tree.parent(best_iid)
            if parent:
                self.tree.item(parent, open=True)
            self.tree.selection_set(best_iid)
            self.tree.see(best_iid)
            finding = self._finding_for_iid.get(best_iid)
            if finding:
                self._show_finding(finding)

    def _on_cancel(self) -> None:
        """Request scan cancellation. The check loop won't be interrupted mid-call,
        but no new checks will start once the in-flight one finishes."""
        if not (self._scan_thread and self._scan_thread.is_alive()):
            return
        self._cancel_requested = True
        # If we were paused when cancel was clicked, also clear pause so the
        # scanner can complete the abort instead of looping forever.
        self._pause_requested = False
        self.status_var.set("Cancelling after current check finishes...")
        self.cancel_btn.configure(state=DISABLED)
        self.pause_btn.configure(state=DISABLED, text="Pause")

    # #51 — pause / resume toggles
    def _on_pause(self) -> None:
        """Ctrl+P or Pause button. Toggles between Pause and Resume."""
        if not (self._scan_thread and self._scan_thread.is_alive()):
            return
        if self._pause_requested:
            # Currently paused → resume.
            self._pause_requested = False
            self.pause_btn.configure(text="Pause")
            self.status_var.set("Resumed.")
        else:
            self._pause_requested = True
            self.pause_btn.configure(text="Resume")
            self.status_var.set("Paused — running check will finish, then the loop blocks.")

    # ---------- Tools menu ----------

    def _open_payload_tester(self) -> None:
        from .gui_payloads import open_payload_tester
        default = ""
        if not getattr(self.url_entry, "_placeholder_active", False):
            default = (self.url_var.get() or "").strip()
        open_payload_tester(self, default_url=default)

    # ---------- Scan profiles ----------

    def _rebuild_profiles_menu(self) -> None:
        from . import history as _history
        self._profiles_menu.delete(0, "end")
        profiles = _history.load_profiles()
        if not profiles:
            self._profiles_menu.add_command(label="(no saved profiles)", state=DISABLED)
            return
        for name in sorted(profiles):
            self._profiles_menu.add_command(label=f"Load: {name}",
                                            command=lambda n=name: self._load_profile(n))
        self._profiles_menu.add_separator()
        for name in sorted(profiles):
            self._profiles_menu.add_command(label=f"Delete: {name}",
                                            command=lambda n=name: self._delete_profile(n))

    # ---- #8 / #1 / #2 / #11 side windows ----

    def _open_settings(self) -> None:
        from . import gui_windows as _gw
        _gw.open_settings(self)

    def _open_multitarget(self) -> None:
        from . import gui_windows as _gw
        _gw.open_multitarget(self)

    def _open_schedule(self) -> None:
        from . import gui_windows as _gw
        _gw.open_schedule(self)

    def _open_trend(self) -> None:
        from . import gui_windows as _gw
        _gw.open_trend(self)

    def _on_group_by_owasp_toggle(self) -> None:
        """C2: rebuild the tree grouped by OWASP Top-10 category instead of by check_id.

        Implementation: when ON, we re-build the tree's parent rows from the OWASP
        chips on every check (data from tags.py). Findings then attach to those
        OWASP parents instead of the check parents."""
        if not self._current_report:
            return
        if self.group_by_owasp_var.get():
            self._rebuild_tree_by_owasp()
        else:
            self._rebuild_tree_by_check()

    def _rebuild_tree_by_owasp(self) -> None:
        """C2: rebuild tree with A01-A10 parents, findings underneath."""
        from . import tags as _ctags
        # Remember the current report; tear down the tree
        for iid in list(self.tree.get_children("")):
            self.tree.delete(iid)
        self._check_rows.clear()
        self._finding_for_iid.clear()
        owasp_buckets: dict[str, list[tuple]] = {}  # "A03:2021 Injection" -> [(check_id, finding), ...]
        for r in self._current_report.results:
            tg = _ctags.get_tags(r.check_id)
            owasp = "(unmapped)"
            if tg and tg.get("owasp"):
                owasp = f"{tg['owasp']} {tg.get('owasp_label','')}".strip()
            for f in r.findings:
                owasp_buckets.setdefault(owasp, []).append((r.check_id, r.check_name, f))
        for owasp in sorted(owasp_buckets.keys()):
            findings = owasp_buckets[owasp]
            parent = self.tree.insert("", "end",
                                       text=f"⊟ {owasp}  [{len(findings)} finding(s)]",
                                       tags=("check",), open=True)
            self._check_rows[f"_owasp_{owasp}"] = parent
            for cid, cname, f in findings:
                row_text = f"{f.severity.upper():>8}  {f.title[:120]}  ·  {cname}"
                child = self.tree.insert(parent, "end", text=row_text, tags=(f.severity,))
                self._finding_for_iid[child] = f

    def _rebuild_tree_by_check(self) -> None:
        """C2: rebuild tree with the original per-check parents (default view)."""
        for iid in list(self.tree.get_children("")):
            self.tree.delete(iid)
        self._check_rows.clear()
        self._finding_for_iid.clear()
        for r in self._current_report.results:
            parent = self.tree.insert("", "end",
                                       text=f"✓  {r.check_name}  [{len(r.findings)} finding(s)]",
                                       values=("info",), tags=("check",), open=False)
            self._check_rows[r.check_id] = parent
            if r.error:
                self.tree.insert(parent, "end", text=r.error, values=("error",), tags=("err",))
            else:
                for f in r.findings:
                    row_text = f"{f.severity.upper():>8}  {f.title[:120]}"
                    child = self.tree.insert(parent, "end", text=row_text, tags=(f.severity,))
                    self._finding_for_iid[child] = f
        self._apply_filter()

    def _open_disable_grid(self) -> None:
        """C1: per-check disable grid."""
        from . import gui_windows as _gw
        _gw.open_disable_grid(self)

    def _open_history_search(self) -> None:
        """C3: search across saved JSON reports."""
        from . import gui_windows as _gw
        _gw.open_history_search(self)

    def _open_multi_trend(self) -> None:
        """E8: overlay sparklines for all URLs with >=2 snapshots."""
        from . import gui_windows as _gw
        _gw.open_multi_trend(self)

    def _open_snapshot_diff(self) -> None:
        from . import gui_windows as _gw
        _gw.open_snapshot_diff_pane(self)

    def _open_saved_sites(self) -> None:
        from . import gui_windows as _gw
        _gw.open_saved_sites(self)

    def _open_check_heatmap(self) -> None:
        """#47 — render an SVG heatmap of (check_id × recent snapshots) for
        the current URL, open it in the browser."""
        target = self.url_var.get().strip()
        if not target:
            messagebox.showinfo(APP_NAME, "Enter a URL first.")
            return
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        from . import history as _h
        import json as _json
        import tempfile, webbrowser
        snaps = _h.snapshot_history(target)[-12:]
        if len(snaps) < 2:
            messagebox.showinfo(APP_NAME,
                f"Need at least 2 saved snapshots for {target}; "
                f"found {len(snaps)}.")
            return
        scans: list[tuple[str, dict[str, str]]] = []  # (ts, {check_id: worst_sev})
        all_check_ids: set[str] = set()
        for sp in snaps:
            try:
                d = _json.loads(sp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            ts = d.get("scanned_at", sp.stem.split("-")[-1])[:19]
            worst_by_cid: dict[str, str] = {}
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            for r in d.get("results", []) or []:
                cid = r.get("check_id", "")
                if not cid:
                    continue
                cur = worst_by_cid.get(cid, "")
                for f in r.get("findings", []) or []:
                    sev = f.get("severity", "info")
                    if rank.get(sev, 0) > rank.get(cur, -1):
                        cur = sev
                if cur:
                    worst_by_cid[cid] = cur
                    all_check_ids.add(cid)
            scans.append((ts, worst_by_cid))
        # Build an inline SVG. Rows = checks (only those that fired at
        # least once), cols = scans.
        rows = sorted(all_check_ids)
        if not rows:
            messagebox.showinfo(APP_NAME, "No findings across recent snapshots — nothing to plot.")
            return
        cell_w, cell_h = 60, 18
        label_w = 220
        header_h = 30
        w = label_w + cell_w * len(scans) + 16
        h = header_h + cell_h * len(rows) + 16
        colors = {"critical": "#67000d", "high": "#5a1816", "medium": "#4a3a10",
                   "low": "#133246", "info": "#21262d", "": "#1f1f1f"}
        svg_parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}"'
            f' style="background:#0d1117;color:#e6edf3;font:11px sans-serif">',
        ]
        # Column headers
        for ci, (ts, _) in enumerate(scans):
            x = label_w + ci * cell_w + cell_w // 2
            svg_parts.append(
                f'<text x="{x}" y="{header_h - 4}" fill="#8b949e" '
                f'text-anchor="middle" font-size="9" '
                f'transform="rotate(-30 {x},{header_h - 4})">{ts[:16]}</text>'
            )
        # Rows
        for ri, cid in enumerate(rows):
            y = header_h + ri * cell_h
            svg_parts.append(
                f'<text x="8" y="{y + cell_h - 4}" fill="#e6edf3">{cid[:32]}</text>'
            )
            for ci, (_ts, worst) in enumerate(scans):
                sev = worst.get(cid, "")
                color = colors[sev]
                x = label_w + ci * cell_w
                svg_parts.append(
                    f'<rect x="{x}" y="{y}" width="{cell_w - 1}" '
                    f'height="{cell_h - 1}" fill="{color}"/>'
                )
        svg_parts.append("</svg>")
        svg = "".join(svg_parts)
        html_doc = (
            "<!doctype html><meta charset='utf-8'>"
            f"<title>WPSecScan check-history heatmap — {target}</title>"
            "<body style='background:#0d1117;color:#e6edf3;font:14px sans-serif;margin:24px'>"
            f"<h2>Check-history heatmap — {target}</h2>"
            "<p>Each cell is the worst severity that check produced on that scan. "
            "Empty cells = check fired info-only or wasn't run.</p>"
            f"<div>{svg}</div></body></html>"
        )
        out_path = Path(tempfile.gettempdir()) / "wpsecscan-heatmap.html"
        out_path.write_text(html_doc, encoding="utf-8")
        webbrowser.open(out_path.as_uri())

    def _open_saved_report(self) -> None:
        """#55: open a saved JSON report from disk into the current view."""
        from tkinter import filedialog
        import json as _json
        from .reporters import json_out as _jo  # noqa: PLC0415

        path = filedialog.askopenfilename(
            title="Open saved WPSecScan JSON report",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            data = _json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            messagebox.showerror(APP_NAME, f"Cannot read report: {e}")
            return
        if not isinstance(data, dict) or "target" not in data or "results" not in data:
            messagebox.showerror(APP_NAME, "Not a WPSecScan JSON report.")
            return
        # Rebuild a ScanReport from the JSON so the existing rendering paths
        # work without modification.
        try:
            report = _jo.from_dict(data) if hasattr(_jo, "from_dict") else None
        except Exception:  # noqa: BLE001
            report = None
        if report is None:
            # Fallback: build it manually.
            from .models import Finding, CheckResult, ScanReport
            results = []
            for r in data.get("results", []) or []:
                findings = []
                for f in (r.get("findings") or []):
                    try:
                        findings.append(Finding(
                            severity=f.get("severity", "info"),
                            title=f.get("title", ""),
                            evidence=f.get("evidence", ""),
                            remediation=f.get("remediation", ""),
                            url=f.get("url", ""),
                            extra=f.get("extra") or {},
                        ))
                    except ValueError:
                        continue
                results.append(CheckResult(
                    check_id=r.get("check_id", ""),
                    check_name=r.get("check_name", r.get("check_id", "")),
                    findings=findings,
                    error=r.get("error"),
                    duration_ms=int(r.get("duration_ms") or 0),
                ))
            report = ScanReport(
                target=data.get("target", ""),
                scanned_at=data.get("scanned_at", ""),
                duration_ms=int(data.get("duration_ms") or 0),
                results=results,
            )
        self._current_report = report
        if hasattr(self, "_populate_tree"):
            self._populate_tree(report)
        self.status_var.set(f"Opened: {Path(path).name} — {len(report.all_findings)} findings.")
        self._toast(f"✓ Loaded {Path(path).name}", duration_ms=4000)

    def _open_diff_viewer(self) -> None:
        """E4: launch the standalone two-report HTML viewer in the browser."""
        from . import gui_windows as _gw
        _gw.open_diff_viewer(self)

    def _open_drill_by_tag(self) -> None:
        """E7: drill historical findings by OWASP / ATT&CK / CWE / D3FEND tag."""
        from . import gui_windows as _gw
        _gw.open_drill_by_tag(self)

    def _open_tutorial(self) -> None:
        """E10: 5-step guided tour."""
        from . import gui_windows as _gw
        _gw.open_tutorial(self)

    def _open_marketplace(self) -> None:
        """F5: browse the static drop-in catalogue."""
        from . import gui_windows as _gw
        _gw.open_marketplace(self)

    def _open_onboarding_wizard(self) -> None:
        """O49: token-setup wizard (any time, not just first run)."""
        from . import gui_windows as _gw
        _gw.open_onboarding_wizard(self)

    def _run_demo(self) -> None:
        """Round-56: synthetic scan that visibly exercises every feature.

        Switches the right-side notebook to the Activity tab so the user
        immediately sees the events scrolling in. Runs in a background
        thread so the GUI stays responsive."""
        import threading as _th
        import time as _tm

        try:
            self._right_notebook.select(1)
        except Exception:  # noqa: BLE001
            pass

        try:
            from . import demo as _demo
            from . import activity as _act
        except ImportError:
            return

        def _worker():
            _act.clear()
            report = _demo.build_demo_report()
            for cr in report.results:
                for f in cr.findings:
                    _act.emit("check", f"[{f.severity.upper()}] {cr.check_id}: {f.title[:60]}")
                    _tm.sleep(0.06)
            for cat, msg in _demo.DEMO_ACTIVITY:
                _act.emit(cat, msg)
                _tm.sleep(0.06)
            # Write artifacts to the demo dir
            from .history import _home as _h_home
            from pathlib import Path as _Path
            out_dir = _Path(_h_home()) / "demo"
            try:
                _demo.write_artifacts(report, out_dir)
            except Exception:  # noqa: BLE001
                pass
            # Toast on the GUI thread
            try:
                self.root.after(0, lambda: self._toast(
                    f"Demo finished — artifacts in {out_dir}", duration_ms=8000))
            except Exception:  # noqa: BLE001
                pass

        _th.Thread(target=_worker, daemon=True).start()
        self.status_var.set("Demo mode: synthetic scan running — switch to Activity tab")

    def _init_locale_var(self):
        """O48: initialise the language radio-button StringVar from saved pref."""
        from . import i18n as _i18n
        saved = self._load_pref("locale", "en") if hasattr(self, "_load_pref") else "en"
        _i18n.set_locale(saved)
        self._locale_var = StringVar(value=saved)
        return self._locale_var

    def _on_locale_change(self, code: str) -> None:
        """O48: persist + apply locale change. Re-rendering existing widgets is
        a heavier change; for now we just persist + flag the user that a restart
        applies the new strings everywhere."""
        from . import i18n as _i18n
        _i18n.set_locale(code)
        if hasattr(self, "_save_pref"):
            self._save_pref("locale", code)
        try:
            messagebox.showinfo(
                APP_NAME,
                f"Language switched to {code.upper()}. Restart the app to apply translations everywhere.",
            )
        except Exception:  # noqa: BLE001
            pass

    def _open_playbook_walker(self, check_id: str, check_name: str) -> None:
        """E3: step-by-step playbook walker for the given check."""
        from . import gui_windows as _gw
        _gw.open_playbook_walker(self, {
            "check_id": check_id,
            "check_name": check_name,
            "target": (self.url_var.get() or "").strip(),
        })

    def _open_recommendations(self) -> None:
        """C5: show the plugin / config recommendations from the latest scan."""
        if not self._current_report:
            messagebox.showinfo(APP_NAME, "Run a scan first.")
            return
        from . import recommend as _rec
        recs = _rec.recommendations_for(self._current_report)
        win = _tk_mod.Toplevel(self.root)
        win.title("Fix recommendations")
        win.configure(bg=BG)
        win.transient(self.root)
        win.bind("<Escape>", lambda _e: win.destroy())
        body = ttk.Frame(win, padding=14)
        body.pack(fill="both", expand=True)
        if not recs:
            ttk.Label(body, text="No fix recommendations for the current scan — looks clean.",
                      foreground=MUTED).pack(anchor="w")
        else:
            ttk.Label(body, text=f"Recommended fixes from this scan ({len(recs)}):",
                      font=("Segoe UI", 11, "bold"), foreground=FG).pack(anchor="w", pady=(0, 10))
            for rec in recs:
                row = ttk.Frame(body, padding=(0, 4, 0, 8))
                row.pack(fill="x", anchor="w")
                ttk.Label(row, text=f"→ {rec['title']}", font=("Segoe UI", 10, "bold"), foreground=ACCENT).pack(anchor="w")
                ttk.Label(row, text=f"Plugin: {rec['plugin']}", foreground=FG).pack(anchor="w", padx=(16, 0))
                ttk.Label(row, text=f"Why: {rec['why']}", foreground=MUTED, wraplength=520, justify="left").pack(anchor="w", padx=(16, 0))
                cmd_frame = ttk.Frame(row)
                cmd_frame.pack(anchor="w", padx=(16, 0), pady=(4, 0))
                ttk.Label(cmd_frame, text="Command:", foreground=MUTED).pack(side="left")
                ttk.Label(cmd_frame, text=rec["wp_cli"], font=("Consolas", 9), foreground="#79c0ff",
                          background=PANEL2, padding=(6, 2)).pack(side="left", padx=(6, 0))
                ttk.Label(row, text=f"Triggered by: {', '.join(rec['triggered_by'])}",
                          foreground=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=(16, 0), pady=(2, 0))
        ttk.Button(body, text="Close", command=win.destroy).pack(anchor="e", pady=(12, 0))

    def _save_profile_prompt(self) -> None:
        from tkinter import simpledialog
        from . import history as _history
        name = simpledialog.askstring(APP_NAME, "Profile name:")
        if not name or not name.strip():
            return
        name = name.strip()
        # #9: warn before silently overwriting an existing profile.
        existing = _history.load_profiles()
        if name in existing:
            ok = messagebox.askyesno(
                APP_NAME,
                f"A profile named '{name}' already exists.\n\nOverwrite it?",
                icon="warning",
            )
            if not ok:
                self.status_var.set("Save cancelled.")
                return
        try:
            dt_a = int(self.deep_throttle_attempts_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            dt_a = 120
        try:
            dt_p = float(self.deep_throttle_pacing_var.get())
        except (_tk_mod.TclError, TypeError, ValueError):
            dt_p = 10.0
        try:
            http_to = float(self.http_timeout_var.get())
            if not 5.0 <= http_to <= 120.0:
                http_to = 15.0
        except (_tk_mod.TclError, TypeError, ValueError):
            http_to = 15.0
        profile = {
            "aggressive": bool(self.aggressive_var.get()),
            "prove": bool(self.prove_var.get()),
            "deep_throttle": bool(self.deep_throttle_var.get()),
            "deep_throttle_attempts": dt_a,
            "deep_throttle_pacing_s": dt_p,
            "http_timeout_s": http_to,
            "save_reports": bool(self.save_reports_var.get()),
            "auth_user": self.auth_user_var.get().strip(),
            "auth_pass": self.auth_pass_var.get(),
        }
        _history.save_profile(name, profile)
        self._rebuild_profiles_menu()
        self.status_var.set(f"Profile '{name}' saved.")

    def _load_profile(self, name: str) -> None:
        from . import history as _history
        profiles = _history.load_profiles()
        p = profiles.get(name) or {}
        self.aggressive_var.set(bool(p.get("aggressive")))
        self.prove_var.set(bool(p.get("prove")))
        self.deep_throttle_var.set(bool(p.get("deep_throttle")))
        self.deep_throttle_attempts_var.set(int(p.get("deep_throttle_attempts") or 120))
        self.deep_throttle_pacing_var.set(float(p.get("deep_throttle_pacing_s") or 10.0))
        try:
            http_to = float(p.get("http_timeout_s") or 15.0)
        except (TypeError, ValueError):
            http_to = 15.0
        self.http_timeout_var.set(max(5.0, min(120.0, http_to)))
        self.save_reports_var.set(bool(p.get("save_reports", True)))
        self.auth_user_var.set(p.get("auth_user", ""))
        self.auth_pass_var.set(p.get("auth_pass", ""))
        self.status_var.set(f"Profile '{name}' loaded.")
        self._refresh_deep_throttle_eta()

    def _delete_profile(self, name: str) -> None:
        from . import history as _history
        _history.delete_profile(name)
        self._rebuild_profiles_menu()
        self.status_var.set(f"Profile '{name}' deleted.")

    # ---------- Diff with last scan ----------

    def _on_diff_last(self) -> None:
        if self._current_report is None:
            return
        from . import history as _history
        from .diff import diff as _diff_fn
        from pathlib import Path
        import tempfile

        prior_path = _history.previous_report_path(self._current_report.target)
        if not prior_path or not prior_path.exists():
            messagebox.showinfo(APP_NAME, "No prior scan of this URL on file yet.\n\nRun another scan to compare.")
            return

        # Persist current report to a temp file so diff() can read both as paths
        from .reporters import json_out as _json_reporter
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
            tf.write(_json_reporter.render(self._current_report))
            current_path = Path(tf.name)
        try:
            d = _diff_fn(prior_path, current_path)
        finally:
            try:
                current_path.unlink()
            except OSError:
                pass

        # Show in a Toplevel
        win = tkinter.Toplevel(self.root)
        win.title(f"Diff: {self._current_report.target}")
        win.geometry("900x600")
        win.configure(bg=BG)
        info = ttk.Label(win, foreground=MUTED, padding=10, text=(
            f"Previous: {d.get('old_scanned_at', '?')}\n"
            f"Current:  {d.get('new_scanned_at', '?')}\n"
            f"NEW: {len(d['new'])} · RESOLVED: {len(d['resolved'])} · UNCHANGED: {d['unchanged']}"
        ))
        info.pack(side="top", fill="x")
        text = tkinter.Text(win, bg=PANEL, fg=FG, wrap="word", font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        # Use the same readonly helper as the detail pane
        def _ro(event):
            if event.state & 0x4 and event.keysym.lower() in ("c", "a"):
                return None
            if event.keysym in ("Left","Right","Up","Down","Home","End","Page_Up","Page_Down","Tab",
                                "Shift_L","Shift_R","Control_L","Control_R"):
                return None
            return "break"
        text.bind("<KeyPress>", _ro)
        text.tag_configure("new", foreground="#ff8a85", font=("Consolas", 10, "bold"))
        text.tag_configure("res", foreground="#6cc474", font=("Consolas", 10, "bold"))
        text.insert(END, "## NEW since previous scan\n", "new")
        if not d["new"]:
            text.insert(END, "  (none)\n")
        for f in d["new"]:
            text.insert(END, f"  [{f.get('severity','?').upper()}] {f.get('title','')}\n")
        text.insert(END, "\n## RESOLVED since previous scan\n", "res")
        if not d["resolved"]:
            text.insert(END, "  (none)\n")
        for f in d["resolved"]:
            text.insert(END, f"  [{f.get('severity','?').upper()}] {f.get('title','')}\n")

    # ---------- Defender false-positive helpers ----------

    def _defender_ack_path(self) -> Path:
        from . import history as _h
        return Path(_h._home()) / "first_run_acknowledged.json"

    # ---------- Round-S misc helpers ----------

    def _load_pref(self, key: str, default):
        """Cheap key/value preference store backed by ~/.wpsecscan/prefs.json."""
        try:
            from . import history as _h
            import json as _j
            p = Path(_h._home()) / "prefs.json"
            if not p.exists():
                return default
            return _j.loads(p.read_text(encoding="utf-8")).get(key, default)
        except (OSError, ValueError, Exception):  # noqa: BLE001
            return default

    def _save_pref(self, key: str, value) -> None:
        try:
            from . import history as _h
            import json as _j
            p = Path(_h._home()) / "prefs.json"
            blob = {}
            if p.exists():
                try:
                    blob = _j.loads(p.read_text(encoding="utf-8")) or {}
                except (OSError, ValueError):
                    blob = {}
            blob[key] = value
            p.write_text(_j.dumps(blob), encoding="utf-8")
        except OSError:
            pass

    def _on_tts_toggle(self) -> None:
        """E9: persist TTS preference."""
        self.tts_enabled = bool(self._tts_menu_var.get())
        self._save_pref("tts_enabled", self.tts_enabled)
        if self.tts_enabled:
            self._speak("Voice readout enabled.")

    def _speak(self, msg: str) -> None:
        """E9: voice readout of the scan summary. Uses pyttsx3 if available,
        falls back to winsound beep. Best-effort, no-op on failure."""
        if not getattr(self, "tts_enabled", False):
            return
        def _worker():
            try:
                import pyttsx3  # type: ignore[import-not-found]
                engine = pyttsx3.init()
                engine.say(msg)
                engine.runAndWait()
                return
            except Exception:  # noqa: BLE001
                pass
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_OK)
            except Exception:  # noqa: BLE001
                pass
        import threading
        threading.Thread(target=_worker, daemon=True).start()

    def _maybe_show_defender_first_run(self):
        """First-launch dialog explaining the Defender false positive.

        Tracked via ~/.wpsecscan/first_run_acknowledged.json so it only shows once.
        Returns the opened Toplevel (or None when skipped) so the first-run
        chain can wait for it to close before opening the next dialog.
        """
        try:
            if self._defender_ack_path().exists():
                return None
        except (OSError, Exception):  # noqa: BLE001
            return None
        return self._open_defender_dialog(is_first_run=True)

    def _maybe_show_tutorial_first_run(self):
        """E10: show the 5-step tutorial once on first launch."""
        try:
            from . import gui_windows as _gw
            if _gw.has_seen_tutorial():
                return None
            return _gw.open_tutorial(self)
        except Exception:  # noqa: BLE001
            return None

    def _maybe_show_onboarding_wizard_first_run(self):
        """O49: show the token-setup wizard once on first launch."""
        try:
            from . import gui_windows as _gw
            if _gw.has_seen_wizard():
                return None
            _gw.mark_wizard_seen()  # mark BEFORE opening so close/cancel still counts
            return _gw.open_onboarding_wizard(self)
        except Exception:  # noqa: BLE001
            return None

    def _run_first_run_chain(self) -> None:
        """UX-036: open the first-run dialogs sequentially, each kicking off
        the next on its ``<Destroy>`` event. Previously the three dialogs were
        fired by hard-coded ``after(200/600/1200ms)`` delays — on a slow PC
        the tutorial could open behind the wizard and the Defender popup
        would steal focus mid-form. Chaining via <Destroy> makes the
        ordering deterministic regardless of how long the user spends on
        any one dialog."""
        steps = [
            self._maybe_show_defender_first_run,
            self._maybe_show_tutorial_first_run,
            self._maybe_show_onboarding_wizard_first_run,
            lambda: self._maybe_show_update_notice() or None,
        ]

        def _run_step(idx: int) -> None:
            if idx >= len(steps):
                return
            try:
                win = steps[idx]()
            except Exception:  # noqa: BLE001 — first-run chain must never crash the app
                win = None
            if win is not None and hasattr(win, "bind"):
                # When this dialog closes, fire the next step.
                win.bind("<Destroy>",
                          lambda _e, _i=idx: (
                              # Tk dispatches <Destroy> for *every* child
                              # widget of the Toplevel as it's torn down;
                              # only act on the Toplevel's own destruction.
                              self.root.after_idle(lambda: _run_step(_i + 1))
                              if str(_e.widget) == str(win) else None
                          ),
                          add="+")
            else:
                # Step was skipped (marker already set) — proceed immediately.
                self.root.after(0, _run_step, idx + 1)

        # Defer the first step until the main window has rendered.
        self.root.after(200, _run_step, 0)

    def _maybe_show_update_notice(self, *, force: bool = False) -> None:
        """Round-57: check GitHub releases on launch. If a newer version is
        available, show a popup with a 'Download' button that opens the
        release page in the browser.

        force=True bypasses the 24-hour cache (used by Help → Check for updates)."""
        try:
            from . import auto_update as _au
            from . import __version__ as _ver
            rel = _au.check_for_update(_ver, channel="stable", force=force)
        except Exception:  # noqa: BLE001
            return
        if not rel:
            if force:
                try:
                    messagebox.showinfo(APP_NAME, f"You're on the latest version (v{_ver}).")
                except Exception:  # noqa: BLE001
                    pass
            return
        tag = rel.get("tag_name", "")
        url = rel.get("html_url", "")
        # Suppress the popup if the user already saw this tag and clicked Later
        suppressed = self._load_pref("update_dismissed_tag", "") if hasattr(self, "_load_pref") else ""
        if suppressed == tag and not force:
            return

        win = _tk_mod.Toplevel(self.root)
        win.title("Update available")
        win.configure(bg=BG)
        win.transient(self.root)
        win.geometry("460x180")
        win.bind("<Escape>", lambda _e: win.destroy())

        body = ttk.Frame(win, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=f"WPSecScan {tag} is available", font=("Segoe UI", 13, "bold"),
                  foreground="#79c0ff").pack(anchor="w")
        ttk.Label(body, text=f"You're on v{_ver}.", foreground=MUTED).pack(anchor="w", pady=(2, 12))
        ttk.Label(body, text=("Updates ship as new wpsecscan.exe + wpsecscan-gui.exe files. "
                              "Click Download to open the release page, grab both binaries, "
                              "and drop them in place of the current ones."),
                  wraplength=420, foreground=FG).pack(anchor="w")

        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(14, 0))

        def _open_download():
            import webbrowser
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001
                pass
            win.destroy()

        def _later():
            try:
                if hasattr(self, "_save_pref"):
                    self._save_pref("update_dismissed_tag", tag)
            except Exception:  # noqa: BLE001
                pass
            win.destroy()

        ttk.Button(btns, text="Download", style="Accent.TButton", command=_open_download).pack(side="left")
        ttk.Button(btns, text="Later", command=_later).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")

    def _open_defender_dialog(self, is_first_run: bool = False):  # returns Toplevel or None
        """Dialog explaining why Windows Defender may flag this binary and offering
        a one-click 'add exclusion' button + a 'copy command' button."""
        win = _tk_mod.Toplevel(self.root)
        win.title("About Windows Defender warnings")
        win.configure(bg=BG)
        win.transient(self.root)
        win.resizable(False, False)
        win.bind("<Escape>", lambda _e: win.destroy())

        body = ttk.Frame(win, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Heads-up about Windows Defender",
                  font=("Segoe UI", 13, "bold"), foreground=FG).pack(anchor="w")
        ttk.Label(body, text="", font=("Segoe UI", 3)).pack()
        msg = (
            "WPSecScan is a defensive security scanner. To DETECT known webshells "
            "(China Chopper, c99, r57…) on your sites, the binary has to contain "
            "references to those attack patterns by design.\n\n"
            "Windows Defender's heuristic engine sometimes pattern-matches the .exe "
            "and flags it as `Backdoor:JS/Chopper.GG!dha`. This is a documented "
            "false positive — sqlmap, Metasploit, nuclei, and Gophish all trip the "
            "same kind of detection.\n\n"
            "What this program does NOT do:\n"
            "  • It is not a backdoor.\n"
            "  • It does not run on remote machines.\n"
            "  • It does not exfiltrate data.\n"
            "  • It only sends HTTP requests to URLs YOU type in.\n\n"
            "You have three options:"
        )
        ttk.Label(body, text=msg, foreground=FG, wraplength=540, justify="left").pack(anchor="w")
        ttk.Label(body, text="", font=("Segoe UI", 3)).pack()

        opts_frame = ttk.Frame(body)
        opts_frame.pack(anchor="w", pady=(4, 8))

        opt1 = ttk.Frame(opts_frame); opt1.pack(anchor="w", pady=2)
        ttk.Label(opt1, text="1. ", foreground=ACCENT, font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(opt1, text="Add a Defender exclusion (one-click, needs admin via UAC):",
                  foreground=FG, wraplength=480).pack(side="left")

        opt2 = ttk.Frame(opts_frame); opt2.pack(anchor="w", pady=2)
        ttk.Label(opt2, text="2. ", foreground=ACCENT, font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(opt2, text="Copy the PowerShell command — run it yourself when convenient",
                  foreground=FG, wraplength=480).pack(side="left")

        opt3 = ttk.Frame(opts_frame); opt3.pack(anchor="w", pady=2)
        ttk.Label(opt3, text="3. ", foreground=ACCENT, font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(opt3, text="Do nothing — proceed without an exclusion (you'll restore from quarantine if needed)",
                  foreground=FG, wraplength=480).pack(side="left")

        if is_first_run:
            self._dont_show_var = BooleanVar(value=True)
            ttk.Checkbutton(body, text="Don't show this on every startup",
                            variable=self._dont_show_var).pack(anchor="w", pady=(4, 0))

        btn_row = ttk.Frame(body)
        btn_row.pack(fill="x", pady=(10, 0))

        def _ack_and_close():
            # Honour the "Don't show this on every startup" checkbox — only write the
            # ack file if it's set (default True; user can uncheck to keep seeing it).
            wants_ack = True
            if is_first_run:
                try:
                    wants_ack = bool(self._dont_show_var.get())
                except (_tk_mod.TclError, AttributeError):
                    wants_ack = True
            if is_first_run and wants_ack:
                try:
                    import json as _j, time as _t
                    self._defender_ack_path().parent.mkdir(parents=True, exist_ok=True)
                    self._defender_ack_path().write_text(_j.dumps({"ts": _t.time()}), encoding="utf-8")
                except OSError:
                    pass
            win.destroy()

        def _run_exclusion():
            self._run_defender_exclusion()
            _ack_and_close()

        def _copy_cmd():
            cmd = self._defender_exclusion_command()
            self.root.clipboard_clear()
            self.root.clipboard_append(cmd)
            self._toast("✓ Exclusion command copied — paste in admin PowerShell", duration_ms=8000)
            _ack_and_close()

        ttk.Button(btn_row, text="Add exclusion now (UAC)", command=_run_exclusion,
                   style="Accent.TButton").pack(side="left")
        ttk.Button(btn_row, text="Copy command", command=_copy_cmd).pack(side="left", padx=(6, 0))
        ttk.Button(btn_row, text="Close", command=_ack_and_close).pack(side="right")

        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() // 2) - (win.winfo_width() // 2)
        y = self.root.winfo_rooty() + 100
        win.geometry(f"+{x}+{y}")
        return win

    @staticmethod
    def _ps_single_quote(s: str) -> str:
        """Escape a string for use inside PowerShell single quotes.

        PowerShell escapes a literal `'` by doubling it (`''`). Spaces are fine
        inside single quotes, but apostrophes in a user's profile name (e.g.
        `C:\\Users\\O'Brien\\...`) would otherwise close the quote early.
        """
        return s.replace("'", "''")

    def _defender_exclusion_command(self) -> str:
        """Build the actual PowerShell command, with the running binary's directory."""
        import sys as _sys
        if getattr(_sys, "frozen", False):
            exe_dir = str(Path(_sys.executable).parent)
        else:
            exe_dir = str(Path.cwd() / "dist")
        safe_dir = self._ps_single_quote(exe_dir)
        # Single-line, easy to paste:
        return (
            f"Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-Command',"
            f"\"Add-MpPreference -ExclusionPath '{safe_dir}'; Read-Host 'Done. Press Enter'\""
        )

    def _run_defender_exclusion(self) -> None:
        r"""Layer 3: invoke add-defender-exclusion.ps1 via UAC.

        Tries the bundled scripts\ path first, falls back to an inline command
        if the script isn't where we expect."""
        import sys as _sys
        import subprocess
        try:
            if getattr(_sys, "frozen", False):
                exe_path = _sys.executable
                base = Path(exe_path).parent
                # PyInstaller bundles ps1 under _MEIPASS\scripts\.
                meipass = getattr(_sys, "_MEIPASS", None)
                ps_script = (Path(meipass) / "scripts" / "add-defender-exclusion.ps1") if meipass else None
            else:
                exe_path = str(Path.cwd() / "dist" / "wpsecscan.exe")
                base = Path.cwd()
                ps_script = base / "scripts" / "add-defender-exclusion.ps1"
            # Fall back to the development path next to the project root
            if not ps_script or not ps_script.exists():
                ps_script = base.parent / "scripts" / "add-defender-exclusion.ps1"
            if ps_script.exists():
                # We have to use Start-Process -Verb RunAs for UAC. Wrap via a one-liner.
                # Single-quote-escape each path that goes inside `'...'` so spaces
                # AND apostrophes in a user's profile path are handled correctly.
                safe_script = self._ps_single_quote(str(ps_script))
                safe_exe = self._ps_single_quote(exe_path)
                subprocess.Popen([
                    "powershell", "-NoProfile", "-Command",
                    (
                        "Start-Process powershell -Verb RunAs -ArgumentList "
                        f"'-NoProfile','-ExecutionPolicy','Bypass','-File','{safe_script}',"
                        f"'-ExePath','{safe_exe}'"
                    )
                ], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._toast("✓ Launching UAC prompt — accept to add exclusion", duration_ms=8000)
                return
            # Fallback: inline Add-MpPreference via UAC
            exe_dir = str(Path(exe_path).parent)
            safe_dir = self._ps_single_quote(exe_dir)
            subprocess.Popen([
                "powershell", "-NoProfile", "-Command",
                (
                    "Start-Process powershell -Verb RunAs -ArgumentList "
                    "'-NoProfile','-Command',"
                    f"\"Add-MpPreference -ExclusionPath '{safe_dir}'; "
                    "Write-Host 'Done.' -ForegroundColor Green; Start-Sleep 3\""
                )
            ], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._toast("✓ Launching UAC prompt — accept to add exclusion", duration_ms=8000)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(
                APP_NAME,
                f"Couldn't launch the exclusion helper automatically:\n\n{e}\n\n"
                "Open admin PowerShell and run:\n"
                f"  Add-MpPreference -ExclusionPath '{Path(_sys.executable).parent}'"
            )

    def _show_shortcuts(self) -> None:
        messagebox.showinfo(
            f"{APP_NAME} — Keyboard shortcuts",
            "F5             Start scan\n"
            "Esc            Cancel scan\n"
            "Ctrl+L         Focus the URL field\n"
            "Ctrl+T         Open Payload Tester\n"
            "Ctrl+E         Expand all tree rows\n"
            "Ctrl+W         Collapse all tree rows\n"
            "Ctrl+Down      Next finding (across all checks)\n"
            "Ctrl+Up        Previous finding\n"
            "Ctrl+H         Open the last saved HTML report\n"
            "Ctrl+J         Copy JSON of current report\n"
            "\n"
            "In the detail pane: select text + Ctrl+C to copy.\n"
            "Right-click any finding in the tree for Copy URL / curl / markdown.",
        )

    def _show_about(self) -> None:
        """#15: About as non-modal Toplevel so the user can keep it open while scanning."""
        # Singleton
        if hasattr(self, "_about_win") and self._about_win is not None and self._about_win.winfo_exists():
            self._about_win.lift()
            self._about_win.focus_force()
            return
        from .checks import ALL_CHECKS
        from .payloads import load_payloads
        try:
            n_payloads = len(load_payloads())
        except Exception:  # noqa: BLE001
            n_payloads = 0
        try:
            import json
            sig_path = Path(__file__).resolve().parent / "data" / "exploit_signatures.json"
            n_sigs = len(json.loads(sig_path.read_text(encoding="utf-8"))["signatures"])
        except Exception:  # noqa: BLE001
            n_sigs = 0
        win = _tk_mod.Toplevel(self.root)
        self._about_win = win
        win.title(f"About {APP_NAME}")
        win.configure(bg=BG)
        win.transient(self.root)
        win.resizable(False, False)
        win.bind("<Destroy>", lambda _e, w=win: setattr(self, "_about_win", None) if getattr(self, "_about_win", None) is w else None)
        win.bind("<Escape>", lambda _e: win.destroy())
        body = ttk.Frame(win, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=APP_NAME, font=("Segoe UI", 14, "bold"), foreground=FG).pack(anchor="w")
        ttk.Label(body, text=f"version {__version__}", foreground=MUTED).pack(anchor="w")
        ttk.Label(body, text="", font=("Segoe UI", 4)).pack()  # spacer
        ttk.Label(body, text="Defensive WordPress security scanner. Use only on sites you own.",
                  foreground=FG, wraplength=400).pack(anchor="w")
        ttk.Label(body, text="", font=("Segoe UI", 4)).pack()
        ttk.Label(body, text=(
            f"  • {len(ALL_CHECKS)} checks\n"
            f"  • {n_payloads} curated read-only payloads (Payload Tester)\n"
            f"  • {n_sigs} confirmable CVE signatures"
        ), foreground=FG, justify="left").pack(anchor="w")
        ttk.Label(body, text="", font=("Segoe UI", 4)).pack()
        ttk.Label(body, text=(
            "No bulk online brute force, no auto-exploitation, no write payloads.\n"
            "For real password testing: hashcat against your own DB hash dump.\n"
            "For real exploit testing: sqlmap / Metasploit, per-target."
        ), foreground=MUTED, justify="left").pack(anchor="w")
        ttk.Button(body, text="Close", command=win.destroy).pack(anchor="e", pady=(14, 0))

    # ---------- Tree controls ----------

    def _expand_all(self) -> None:
        for iid in self.tree.get_children(""):
            self.tree.item(iid, open=True)

    def _collapse_all(self) -> None:
        for iid in self.tree.get_children(""):
            self.tree.item(iid, open=False)

    def _on_sort_toggle(self) -> None:
        """Sort tree parent rows by worst severity (critical first), or restore original order."""
        if not self.tree.get_children(""):
            return
        if self.sort_severity_var.get():
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
            parents = list(self.tree.get_children(""))
            def worst_sev(parent_iid):
                worst = None
                for child in self.tree.get_children(parent_iid):
                    f = self._finding_for_iid.get(child)
                    if not f:
                        continue
                    if worst is None or sev_rank.get(f.severity, 5) < sev_rank.get(worst, 5):
                        worst = f.severity
                return sev_rank.get(worst, 5)
            parents.sort(key=worst_sev)
            for idx, iid in enumerate(parents):
                self.tree.move(iid, "", idx)
        else:
            # Restore original insertion order from self._check_rows insertion sequence
            for idx, (cid, parent_iid) in enumerate(self._check_rows.items()):
                self.tree.move(parent_iid, "", idx)

    # ---------- Right-click context menu ----------

    def _notify_scan_complete(self, report) -> None:
        """#45 — best-effort OS-level notification when a scan finishes.
        Tries the cross-platform `plyer` package; falls back to a Windows
        winsound beep + Tk window-flash; on macOS / Linux, prints a bell
        char as a last resort."""
        title = f"WPSecScan: {report.target}"
        score = getattr(report, "risk_score", "?")
        s = report.summary if hasattr(report, "summary") else {}
        body = (f"Risk {score}/100  ·  "
                f"crit {s.get('critical',0)} / high {s.get('high',0)} / med {s.get('medium',0)}")
        # Cross-platform notification via plyer if installed.
        try:
            from plyer import notification as _pn  # type: ignore[import-not-found]
            _pn.notify(title=title, message=body, app_name="WPSecScan", timeout=8)
            return
        except (ImportError, Exception):  # noqa: BLE001
            pass
        # Windows fallback: beep + flash window if it's minimized.
        try:
            import winsound  # type: ignore[import-not-found]
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except (ImportError, RuntimeError):
            pass
        # Flash the window if minimized so the user notices.
        try:
            self.root.bell()
            if self.root.state() == "iconic":
                # On Windows, deiconify + lift draws attention.
                self.root.deiconify()
                self.root.lift()
        except Exception:  # noqa: BLE001
            pass

    def _on_tree_double_click(self, event) -> None:
        """#43 — double-click a finding row opens its URL in the system browser."""
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        finding = self._finding_for_iid.get(iid)
        if finding is None or not finding.url:
            return
        try:
            webbrowser.open(finding.url)
        except Exception:  # noqa: BLE001
            pass

    def _on_tree_right_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        # Enable/disable menu items based on what's selected
        finding = self._finding_for_iid.get(iid)
        has_finding = finding is not None
        finding_only_labels = (
            "Copy URL", "Copy curl (replay)", "Open URL in browser", "Copy finding (markdown)",
            "Mark as accepted risk...", "Mark as false positive...", "Clear annotation",
            "Run nuclei tag for this check", "Open in sqlmap (proven param)",
        )
        for label in finding_only_labels:
            try:
                self._ctx_menu.entryconfig(label, state=NORMAL if has_finding else DISABLED)
            except tkinter.TclError:
                pass
        self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _selected_finding_check_id(self) -> str | None:
        """Return the check_id of the currently selected finding (via its tree parent)."""
        sel = self.tree.selection()
        if not sel:
            return None
        parent_iid = self.tree.parent(sel[0]) or sel[0]
        return next((cid for cid, i in self._check_rows.items() if i == parent_iid), None)

    # ---- #3 annotations ----

    def _annotate(self, status: str) -> None:
        f = self._selected_finding()
        cid = self._selected_finding_check_id()
        if f is None or cid is None or self._current_report is None:
            return
        from . import history as _h
        from tkinter import simpledialog
        note = ""
        if status:
            note = simpledialog.askstring(
                APP_NAME, f"Optional note for '{status}':", parent=self.root
            ) or ""
        _h.set_annotation(self._current_report.target, cid, f.title, status, note)
        # Refresh visuals (badge + filter)
        self._refresh_annotation_visuals()
        self.status_var.set(f"Annotation '{status or 'cleared'}' saved." if status else "Annotation cleared.")

    def _refresh_annotation_visuals(self) -> None:
        """Visit every finding row, append/remove an annotation suffix in its label."""
        if self._current_report is None:
            return
        from . import history as _h
        anns = _h.load_annotations().get(self._current_report.target, {})
        for iid, f in list(self._finding_for_iid.items()):
            parent_iid = self.tree.parent(iid)
            cid = next((c for c, i in self._check_rows.items() if i == parent_iid), None)
            if not cid:
                continue
            label = f.title
            ann = anns.get(_h.annotation_fingerprint(cid, f.title))
            if ann:
                tag = {"accepted-risk": "✓ accepted",
                       "false-positive": "✗ false-positive"}.get(ann["status"], ann["status"])
                label = f"{label}   [{tag}]"
            try:
                self.tree.item(iid, text=label)
            except tkinter.TclError:
                pass
        self._apply_filter_pills()

    # ---- G1 / G2 / E3 quick actions ----

    def _ctx_assign_owner(self) -> None:
        """G1: tag the selected finding with an owner (free-form, persisted)."""
        f = self._selected_finding()
        cid = self._selected_finding_check_id()
        if f is None or cid is None or self._current_report is None:
            return
        from . import history as _h
        from tkinter import simpledialog
        current = _h.get_assignee(self._current_report.target, cid, f.title) or ""
        from tkinter import simpledialog as _sd
        new = _sd.askstring(
            APP_NAME,
            f"Assign owner for:\n  {f.title[:80]}\n\n(Empty to clear)",
            initialvalue=current, parent=self.root,
        )
        if new is None:
            return
        _h.set_assignee(self._current_report.target, cid, f.title, new.strip())
        self.status_var.set(f"Assigned to: {new.strip()}" if new.strip() else "Assignment cleared.")

    def _ctx_comments(self) -> None:
        """G2: open a small comments window for the selected finding."""
        f = self._selected_finding()
        cid = self._selected_finding_check_id()
        if f is None or cid is None or self._current_report is None:
            return
        from . import history as _h
        win = _tk_mod.Toplevel(self.root)
        win.title(f"Comments — {f.title[:60]}")
        win.configure(bg=BG)
        win.geometry("560x420")
        win.transient(self.root)
        win.bind("<Escape>", lambda _e: win.destroy())

        body = ttk.Frame(win, padding=12)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text=f.title, font=("Segoe UI", 10, "bold"),
                  wraplength=520).pack(anchor="w")
        ttk.Label(body, text=f"Severity: {f.severity.upper()}   ·   Check: {cid}",
                  foreground=MUTED).pack(anchor="w", pady=(0, 8))

        list_frame = ttk.Frame(body)
        list_frame.pack(fill="both", expand=True)
        lbox = _tk_mod.Listbox(list_frame, bg=PANEL, fg=FG, font=("Segoe UI", 9),
                               selectmode="single", relief="flat", activestyle="none")
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=lbox.yview)
        lbox.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        lbox.pack(side="left", fill="both", expand=True)

        def _reload() -> None:
            lbox.delete(0, "end")
            for c in _h.get_comments(self._current_report.target, cid, f.title):
                import datetime as _dt
                ts = _dt.datetime.fromtimestamp(c.get("ts", 0)).strftime("%Y-%m-%d %H:%M")
                lbox.insert("end", f"[{ts}] {c.get('author', '?')}: {c.get('body', '')[:140]}")

        _reload()

        entry_row = ttk.Frame(body)
        entry_row.pack(fill="x", pady=(8, 0))
        ttk.Label(entry_row, text="Author:").pack(side="left")
        author_var = _tk_mod.StringVar(value="")
        try:
            import getpass
            author_var.set(getpass.getuser())
        except OSError:
            pass
        ttk.Entry(entry_row, textvariable=author_var, width=18).pack(side="left", padx=(4, 8))

        body_var = _tk_mod.StringVar()
        entry_text = ttk.Entry(entry_row, textvariable=body_var)
        entry_text.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def _add() -> None:
            txt = body_var.get().strip()
            if not txt:
                return
            _h.add_comment(self._current_report.target, cid, f.title,
                           author_var.get().strip() or "anonymous", txt)
            body_var.set("")
            _reload()

        def _del() -> None:
            sel = lbox.curselection()
            if not sel:
                return
            if _h.delete_comment(self._current_report.target, cid, f.title, sel[0]):
                _reload()

        ttk.Button(entry_row, text="Add", command=_add).pack(side="left")
        entry_text.bind("<Return>", lambda _e: _add())

        ttk.Button(body, text="Delete selected", command=_del).pack(anchor="e", pady=(8, 0))

    def _ctx_walk_playbook(self) -> None:
        """E3: open the step-by-step playbook walker for the selected finding."""
        f = self._selected_finding()
        cid = self._selected_finding_check_id()
        if f is None or cid is None or self._current_report is None:
            return
        # Find the check_name from results
        cname = next((r.check_name for r in self._current_report.results if r.check_id == cid), cid)
        self._open_playbook_walker(cid, cname)

    # ---- #52 per-check skip from right-click ----

    def _ctx_disable_check(self) -> None:
        cid = self._selected_finding_check_id()
        if not cid:
            return
        from . import gui_windows as _gw
        disabled = _gw.load_disabled_checks()
        if cid in disabled:
            messagebox.showinfo(APP_NAME, f"Check '{cid}' is already disabled.")
            return
        if not messagebox.askyesno(
            APP_NAME,
            f"Disable the '{cid}' check from this point on?\n\n"
            "It will no longer run on any scan from this install. "
            "Re-enable from Settings → 'Enable / disable individual checks…'."
        ):
            return
        disabled.add(cid)
        _gw.save_disabled_checks(disabled)
        self._toast(f"✓ Disabled check '{cid}'. Restart scan to apply.", duration_ms=5000)

    # ---- #15 quick actions ----

    def _ctx_run_nuclei(self) -> None:
        """Launch nuclei in a new shell with the tags for the current finding's check."""
        f = self._selected_finding()
        cid = self._selected_finding_check_id()
        if f is None or cid is None or self._current_report is None:
            return
        from . import playbook as _pb
        raw = _pb.get_playbook(cid)
        nuclei_cmd = None
        if raw and raw.get("nuclei"):
            nuclei_cmd = _pb.substitute(raw, self._current_report.target)["nuclei"][0]
        if not nuclei_cmd:
            nuclei_cmd = f"nuclei -u {self._current_report.target} -tags wordpress"
        # Don't actually run it — copy to clipboard + show message (don't shell out destructive things from a GUI)
        self.root.clipboard_clear()
        self.root.clipboard_append(nuclei_cmd)
        messagebox.showinfo(
            APP_NAME,
            f"Nuclei command copied to clipboard:\n\n{nuclei_cmd}\n\n"
            "Paste in your terminal to run. wpsecscan doesn't run external tools "
            "for you — that's your call."
        )

    def _ctx_open_sqlmap(self) -> None:
        f = self._selected_finding()
        cid = self._selected_finding_check_id()
        if f is None or cid is None or self._current_report is None:
            return
        # Prefer the proven URL from the finding's extra.proof if present
        extra = getattr(f, "extra", {}) or {}
        proven = (extra.get("proof") or {}).get("url") if isinstance(extra.get("proof"), dict) else None
        url = proven or f.url or self._current_report.target
        cmd = f"sqlmap -u '{url}' --batch --random-agent"
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        messagebox.showinfo(
            APP_NAME,
            f"sqlmap command copied to clipboard:\n\n{cmd}\n\n"
            "Paste in your terminal to run. Use only against sites you OWN."
        )

    def _selected_finding(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return self._finding_for_iid.get(sel[0])

    def _ctx_copy_url(self) -> None:
        f = self._selected_finding()
        if not f or not f.url:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(f.url)
        self.status_var.set(f"Copied URL: {f.url}")

    def _ctx_copy_curl(self) -> None:
        f = self._selected_finding()
        if not f:
            return
        replay = (f.extra or {}).get("replay")
        if not replay:
            replay = f"curl -i '{f.url}'" if f.url else "(no replay/curl available for this finding)"
        self.root.clipboard_clear()
        self.root.clipboard_append(replay)
        self._toast("✓ Curl command copied")

    def _ctx_open_browser(self) -> None:
        f = self._selected_finding()
        if not f or not f.url:
            return
        webbrowser.open(f.url)
        self.status_var.set(f"Opened: {f.url}")

    def _ctx_copy_markdown(self) -> None:
        f = self._selected_finding()
        if not f:
            return
        md = (
            f"### [{f.severity.upper()}] {f.title}\n\n"
            f"- URL: {f.url}\n"
            f"\n**Evidence**\n\n```\n{f.evidence}\n```\n"
            f"\n**Remediation**\n\n{f.remediation}\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(md)
        self._toast("✓ Finding copied as markdown")

    # ---- Detail-pane right-click handlers (#4 copy-fix-to-clipboard) ----

    def _detail_copy_selection(self) -> None:
        try:
            sel = self.detail.get("sel.first", "sel.last")
        except _tk_mod.TclError:
            sel = ""
        if not sel:
            self.status_var.set("Nothing selected.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(sel)
        self.status_var.set(f"Copied {len(sel)} chars from detail pane.")

    def _detail_copy_remediation(self) -> None:
        f = getattr(self, "_detail_finding", None)
        if f is None or not f.remediation:
            self.status_var.set("No remediation on the current finding.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(f.remediation)
        self._toast("✓ Remediation copied")

    def _detail_copy_finding_md(self) -> None:
        f = getattr(self, "_detail_finding", None)
        if f is None:
            self.status_var.set("No finding selected.")
            return
        md = (
            f"### [{f.severity.upper()}] {f.title}\n\n"
            f"- URL: {f.url}\n"
            f"\n**Evidence**\n\n```\n{f.evidence}\n```\n"
            f"\n**Remediation**\n\n{f.remediation}\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(md)
        self._toast("✓ Finding copied as markdown")

    def _add_payload_tester_finding(self, finding) -> bool:
        """Called from the PayloadTesterWindow when the user clicks Save as finding.
        Appends the finding to the current report's 'payload_tester' synthetic check.
        Returns True on success, False if no current report yet."""
        if self._current_report is None:
            return False
        # Find or create the synthetic check
        check_id = "payload_tester"
        check_name = "Payload Tester"
        result = next((r for r in self._current_report.results if r.check_id == check_id), None)
        if result is None:
            from .models import CheckResult
            result = CheckResult(check_id=check_id, check_name=check_name)
            self._current_report.results.append(result)
            parent_iid = self.tree.insert("", "end", text=f"~  {check_name}", values=("manual",), tags=("check",))
            self._check_rows[check_id] = parent_iid
        parent_iid = self._check_rows[check_id]
        result.findings.append(finding)
        child = self.tree.insert(
            parent_iid, "end",
            text=finding.title,
            values=(finding.severity.upper(),),
            tags=(finding.severity,),
        )
        self._finding_for_iid[child] = finding
        self.tree.item(parent_iid, open=True)
        self._refresh_summary_live()
        # Update top-level summary
        s = self._current_report.summary
        self.summary_var.set(
            f"Updated — {s['critical']} critical · {s['high']} high · {s['medium']} medium · "
            f"{s['low']} low · {s['info']} info"
        )
        return True

    # ============================================================
    # Round-62 GUI integration — dialogs for new modules.
    # Each dialog is independent + tolerates missing modules gracefully.
    # ============================================================

    def _open_db_status(self) -> None:
        try:
            from . import db as _db
        except ImportError as e:
            messagebox.showerror("DB unavailable", str(e)); return
        s = _db.status()
        age_days = (s["age_seconds"] // 86400) if s["age_seconds"] >= 0 else -1
        msg = (
            f"Source:      {s['source']}\n"
            f"Cache path:  {s['cache_path']}\n"
            f"Cache exists:{s['cache_exists']}\n"
            f"Entries:     {s['entry_count']:,}\n"
            f"Age:         {age_days} days\n"
            f"Stale:       {s['stale']}  (threshold {s['stale_after_seconds'] // 86400} days)\n"
        )
        if messagebox.askyesno("Vulnerability DB status",
                                 msg + "\nRefresh DB now? (downloads from Wordfence + OSV)"):
            try:
                n, p = _db.update_db(verbose=False,
                                       patchstack_token=os.environ.get("WPSECSCAN_PATCHSTACK_TOKEN", ""))
                messagebox.showinfo("DB updated", f"OK — {n:,} entries cached at\n{p}")
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("DB update failed", str(e))

    def _open_sites_dashboard(self) -> None:
        try:
            from . import sites as _sites
        except ImportError as e:
            messagebox.showerror("Sites unavailable", str(e)); return
        rows = _sites.list_sites()
        if not rows:
            messagebox.showinfo("Sites dashboard",
                                  "No sites added yet.\n\n"
                                  "Use the CLI: wpsecscan sites add <URL> --weekly\n"
                                  "Or use Tools → Multi-target scan for one-off batches.")
            return
        import time as _t
        body_lines = []
        for s in rows:
            ts = int(s.get("last_scan_ts") or 0)
            when = "never" if not ts else _t.strftime("%Y-%m-%d", _t.localtime(ts))
            body_lines.append(
                f"{s['url'][:60]:60s}  weekly={s.get('weekly', False)}  "
                f"last={when}  risk={s.get('last_risk_score', '?')}  "
                f"crit={s.get('last_critical', 0)}  high={s.get('last_high', 0)}"
            )
        messagebox.showinfo("Sites dashboard", "\n".join(body_lines[:30]))

    def _open_cve_subscriptions(self) -> None:
        try:
            from . import db as _db
        except ImportError as e:
            messagebox.showerror("DB unavailable", str(e)); return
        subs = _db.subscriptions_load()
        if not subs:
            from tkinter import simpledialog as _sd
            new = _sd.askstring("CVE subscription",
                                 "No subscriptions configured.\n\n"
                                 "Enter a webhook URL to subscribe to new-CVE alerts:")
            if new:
                try:
                    _db.subscribe(new)
                    messagebox.showinfo("Subscribed", f"OK — alerts will POST to {new}")
                except ValueError as e:
                    messagebox.showerror("Invalid", str(e))
            return
        messagebox.showinfo("CVE subscriptions",
                              "\n".join(f"  {s.get('label', '?'):15s}  {s.get('site_url', '*'):30s}  {s.get('webhook_url', '')}"
                                          for s in subs[:20]))

    def _open_proxy_settings(self) -> None:
        try:
            from . import config as _cfg
        except ImportError as e:
            messagebox.showerror("Config unavailable", str(e)); return
        from tkinter import simpledialog as _sd
        cfg = _cfg.load()
        cur_url = cfg.get("proxy_url", "")
        cur_auth = cfg.get("proxy_auth", "")
        new_url = _sd.askstring("Proxy URL",
                                            "Proxy URL (http://, https://, socks5://) — blank to disable:",
                                            initialvalue=cur_url)
        if new_url is None:
            return
        new_auth = _sd.askstring("Proxy auth",
                                             "Optional user:pass — blank for none:",
                                             initialvalue=cur_auth)
        if new_auth is None:
            new_auth = ""
        _cfg.save(proxy_url=new_url.strip(), proxy_auth=new_auth.strip())
        # Best-effort connectivity test
        if new_url.strip():
            try:
                from .integrations.tor_proxy import check_tor_exit
                os.environ["WPSECSCAN_PROXY_URL"] = new_url.strip()
                if new_auth.strip():
                    os.environ["WPSECSCAN_PROXY_AUTH"] = new_auth.strip()
                res = check_tor_exit()
                if res.get("ok"):
                    messagebox.showinfo("Proxy saved",
                                          f"Saved.\nApparent exit IP: {res.get('ip', '?')}"
                                          f"\nis_tor: {res.get('is_tor', False)}")
                else:
                    messagebox.showwarning("Proxy saved (test failed)",
                                             f"Saved but test failed: {res.get('error', 'unknown')}")
            except Exception as e:  # noqa: BLE001
                messagebox.showinfo("Proxy saved", f"Saved (test skipped: {e}).")
        else:
            messagebox.showinfo("Proxy disabled", "Saved — proxy disabled.")

    def _open_mode_picker(self) -> None:
        try:
            from . import config as _cfg
        except ImportError as e:
            messagebox.showerror("Config unavailable", str(e)); return
        cur = _cfg.load().get("mode", "standard")
        from tkinter import simpledialog as _sd
        new = _sd.askstring("User mode",
                                        f"Current mode: {cur}\n\n"
                                        "Choose: beginner / standard / expert\n"
                                        "  - beginner:  basic UI, AI off, aggressive disabled\n"
                                        "  - standard:  current default UI\n"
                                        "  - expert:    expose advanced toggles + experimental features",
                                        initialvalue=cur)
        if not new:
            return
        new = new.strip().lower()
        if new not in ("beginner", "standard", "expert"):
            messagebox.showerror("Invalid", "Mode must be beginner, standard, or expert.")
            return
        _cfg.save(mode=new)
        messagebox.showinfo("Mode saved",
                              f"Saved. Restart the GUI for the new layout to take effect.")

    def _open_bug_report(self) -> None:
        try:
            from . import bug_report
        except ImportError as e:
            messagebox.showerror("Bug-report unavailable", str(e)); return
        from tkinter import simpledialog as _sd
        body = _sd.askstring("Report a bug / feedback",
                                         "Describe what went wrong or what you'd like to see:")
        if not body:
            return
        category = "general"
        if "wrong" in body.lower() or "false" in body.lower():
            category = "wrong_finding"
        elif "feature" in body.lower() or "missing" in body.lower():
            category = "missing_feature"
        url = bug_report.send_feedback(message=body, category=category)
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
        messagebox.showinfo("Bug report",
                              f"Pre-filled GitHub issue opened in your browser.\n\n"
                              f"URL: {url[:160]}...")

    def _open_advanced_ai_options(self) -> None:
        """Round-65 Group C — Advanced AI triage options panel."""
        try:
            from . import ai_triage_ui
            ai_triage_ui.open_advanced_ai_options(self.root)
        except (ImportError, Exception) as e:  # noqa: BLE001
            messagebox.showerror("AI options unavailable", str(e))

    def _open_analytics_options(self) -> None:
        """Round-65 — opt-in local usage analytics."""
        try:
            from . import analytics
        except ImportError as e:
            messagebox.showerror("Analytics unavailable", str(e)); return
        from tkinter import simpledialog as _sd
        st = analytics.status()
        action = _sd.askstring(
            "Usage analytics",
            f"Current status: {'ENABLED' if st['enabled'] else 'DISABLED'}\n"
            f"Events recorded: {st['event_count']}\n"
            f"Anonymous ID: {st['anonymous_id']}\n"
            f"Storage: {st['storage_path']}\n\n"
            "Local-only by default. Nothing is uploaded.\n"
            "Type one of: enable, disable, show, forget, export <path>"
        )
        if not action:
            return
        parts = action.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        if cmd == "enable":
            messagebox.showinfo("Analytics", analytics.enable())
        elif cmd == "disable":
            messagebox.showinfo("Analytics", analytics.disable())
        elif cmd == "show":
            messagebox.showinfo("Analytics — recent events", analytics.show_recent(limit=30))
        elif cmd == "forget":
            messagebox.showinfo("Analytics", analytics.forget())
        elif cmd == "export" and len(parts) == 2:
            messagebox.showinfo("Analytics", analytics.export(parts[1]))
        else:
            messagebox.showerror("Analytics", f"Unknown command: {action}")


def main() -> None:
    import sys
    # Same UTF-8 guard as the CLI, harmless if stdout doesn't support reconfigure.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    root = Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
