"""Auxiliary GUI windows (Settings / Multi-target / Schedule / Trend / Webhook).

Each function takes the parent GUI instance and creates a Toplevel window.
Kept here so gui.py doesn't balloon further.
"""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

# Tiny re-imports — keep this module independent of the main GUI module load order.
BG = "#1c1f24"
FG = "#e6edf3"
MUTED = "#8b949e"
PANEL = "#22262d"
APP_NAME = "WPSecScan"  # B6: previously read but never defined → onboarding wizard crashed.


# ----------------------- #8 Settings window -----------------------

def open_settings(app) -> None:
    """Consolidated tunables: deep-throttle attempts/pacing, Slack/Discord webhook."""
    if hasattr(app, "_settings_win") and app._settings_win is not None and app._settings_win.winfo_exists():
        app._settings_win.lift()
        app._settings_win.focus_force()
        return
    win = tk.Toplevel(app.root)
    app._settings_win = win
    win.title("WPSecScan settings")
    win.configure(bg=BG)
    win.transient(app.root)
    win.bind("<Destroy>", lambda _e, w=win: setattr(app, "_settings_win", None) if getattr(app, "_settings_win", None) is w else None)
    # #6: Esc closes
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=14)
    body.pack(fill="both", expand=True)

    row = 0
    ttk.Label(body, text="Deep throttle mapper", font=("Segoe UI", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", pady=(0, 6)); row += 1
    min_a, max_a, min_p, max_p = app._DT_BOUNDS
    ttk.Label(body, text="Wrong-login attempts:").grid(row=row, column=0, sticky="w", padx=(0, 8))
    ttk.Spinbox(body, from_=min_a, to=max_a, increment=10, width=7,
                textvariable=app.deep_throttle_attempts_var).grid(row=row, column=1, sticky="w")
    ttk.Label(body, text=f"({min_a}–{max_a})", foreground=MUTED).grid(row=row, column=2, sticky="w", padx=(6, 0))
    row += 1
    ttk.Label(body, text="Pacing between attempts (s):").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    ttk.Spinbox(body, from_=min_p, to=max_p, increment=1.0, width=7, format="%.1f",
                textvariable=app.deep_throttle_pacing_var).grid(row=row, column=1, sticky="w", pady=(6, 0))
    ttk.Label(body, text=f"({min_p:.0f}–{max_p:.0f})", foreground=MUTED).grid(row=row, column=2, sticky="w", padx=(6, 0), pady=(6, 0))
    row += 1

    # UX-033: per-request HTTP timeout. Slow targets (Cloudways, behind a
    # WAF, on a CDN cold-cache) routinely take more than the 15s default.
    ttk.Separator(body, orient="horizontal").grid(row=row, column=0, columnspan=3, sticky="ew", pady=12); row += 1
    ttk.Label(body, text="HTTP timeout", font=("Segoe UI", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", pady=(0, 6)); row += 1
    ttk.Label(body, text="Seconds per request:").grid(row=row, column=0, sticky="w", padx=(0, 8))
    if not hasattr(app, "http_timeout_var"):
        # Back-compat for callers that opened Settings before the var existed.
        app.http_timeout_var = tk.DoubleVar(value=15.0)
    ttk.Spinbox(body, from_=5.0, to=120.0, increment=5.0, width=7, format="%.0f",
                textvariable=app.http_timeout_var).grid(row=row, column=1, sticky="w")
    ttk.Label(body, text="(5–120)", foreground=MUTED).grid(row=row, column=2, sticky="w", padx=(6, 0))
    row += 1

    ttk.Separator(body, orient="horizontal").grid(row=row, column=0, columnspan=3, sticky="ew", pady=12); row += 1
    ttk.Label(body, text="Webhook notify (Slack / Discord)", font=("Segoe UI", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", pady=(0, 6)); row += 1
    ttk.Label(body, text="Webhook URL:").grid(row=row, column=0, sticky="w", padx=(0, 8))
    # #10: Slack webhooks are 150+ chars; the old width=44 hid half. Width=72 fits a typical one.
    ttk.Entry(body, textvariable=app.webhook_url_var, width=72).grid(row=row, column=1, columnspan=2, sticky="ew")
    body.columnconfigure(1, weight=1)
    row += 1
    ttk.Label(body, text="Notify on severity ≥:").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    ttk.OptionMenu(body, app.webhook_threshold_var, app.webhook_threshold_var.get() or "high",
                   "critical", "high", "medium", "low").grid(row=row, column=1, sticky="w", pady=(6, 0))
    ttk.Button(body, text="Send test", command=lambda: _webhook_test(app)).grid(row=row, column=2, padx=(8, 0), pady=(6, 0))
    row += 1

    ttk.Separator(body, orient="horizontal").grid(row=row, column=0, columnspan=3, sticky="ew", pady=12); row += 1
    # D2: GitHub Issues integration
    ttk.Label(body, text="GitHub Issues auto-create (opt-in)", font=("Segoe UI", 10, "bold")).grid(
        row=row, column=0, columnspan=3, sticky="w", pady=(0, 6)); row += 1
    ttk.Checkbutton(body, text="Create one GitHub issue per finding after each scan",
                    variable=app.github_enabled_var).grid(row=row, column=0, columnspan=3, sticky="w")
    row += 1
    ttk.Label(body, text="Repo (owner/repo):").grid(row=row, column=0, sticky="w", padx=(0, 8))
    ttk.Entry(body, textvariable=app.github_repo_var, width=42).grid(row=row, column=1, columnspan=2, sticky="ew")
    row += 1
    ttk.Label(body, text="Personal access token:").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    ttk.Entry(body, textvariable=app.github_token_var, width=42, show="*").grid(row=row, column=1, columnspan=2, sticky="ew", pady=(6, 0))
    row += 1
    ttk.Label(body, text="Create issues for severity ≥:").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    ttk.OptionMenu(body, app.github_threshold_var, app.github_threshold_var.get() or "high",
                   "critical", "high", "medium").grid(row=row, column=1, sticky="w", pady=(6, 0))
    row += 1

    ttk.Separator(body, orient="horizontal").grid(row=row, column=0, columnspan=3, sticky="ew", pady=12); row += 1
    # C1 link to disable grid
    ttk.Button(body, text="Enable / disable individual checks...",
               command=lambda: open_disable_grid(app)).grid(row=row, column=0, columnspan=2, sticky="w")
    ttk.Button(body, text="Close", command=win.destroy).grid(row=row, column=2, sticky="e")

    win.update_idletasks()
    x = app.root.winfo_rootx() + (app.root.winfo_width() // 2) - (win.winfo_width() // 2)
    y = app.root.winfo_rooty() + 90
    win.geometry(f"+{x}+{y}")


def _webhook_test(app) -> None:
    """Fire a one-line test message at the configured webhook."""
    from . import notify as _n
    url = app.webhook_url_var.get().strip()
    if not url:
        messagebox.showinfo("Test webhook", "Set a webhook URL first.")
        return
    ok, msg = _n.send_test(url)
    if ok:
        messagebox.showinfo("Test webhook", "✓ Webhook delivered.")
    else:
        messagebox.showerror("Test webhook", f"✗ Failed:\n{msg}")


# ----------------------- #1 Multi-target window -----------------------

def open_multitarget(app) -> None:
    if hasattr(app, "_mt_win") and app._mt_win is not None and app._mt_win.winfo_exists():
        app._mt_win.lift()
        app._mt_win.focus_force()
        return
    win = tk.Toplevel(app.root)
    app._mt_win = win
    win.title("Multi-target scan")
    win.configure(bg=BG)
    win.geometry("700x540")
    win.transient(app.root)
    # Drop the singleton reference when the window is destroyed
    win.bind("<Destroy>", lambda _e, w=win: setattr(app, "_mt_win", None) if getattr(app, "_mt_win", None) is w else None)
    win.bind("<Escape>", lambda _e: win.destroy())  # #6
    win.bind("<Destroy>", lambda _e, w=win: setattr(app, "_mt_win", None) if getattr(app, "_mt_win", None) is w else None)

    body = ttk.Frame(win, padding=12)
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="Paste one URL per line  ·  or use 'Load from file...' to import a .txt list").pack(anchor="w")
    txt_frame = ttk.Frame(body)
    txt_frame.pack(fill="both", expand=True, pady=(4, 8))
    url_text = tk.Text(txt_frame, height=8, wrap="none", bg=PANEL, fg=FG, insertbackground=FG, font=("Consolas", 10))
    url_text.pack(side="left", fill="both", expand=True)
    sb = ttk.Scrollbar(txt_frame, orient="vertical", command=url_text.yview)
    url_text.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")

    # #6: drag-and-drop — accept files dragged onto the Text widget. Best-effort:
    # the optional tkinterdnd2 package enables real OS-level file drops on Windows;
    # without it, the "Load from file..." button below covers the same use case.
    try:
        from tkinterdnd2 import DND_FILES  # type: ignore[import-not-found]
        url_text.drop_target_register(DND_FILES)

        def _on_drop(event):
            # event.data is a brace-quoted, space-joined list of paths on Windows
            raw = event.data
            paths = []
            cur = ""
            in_brace = False
            for ch in raw:
                if ch == '{':
                    in_brace = True; cur = ""
                elif ch == '}':
                    in_brace = False
                    if cur: paths.append(cur); cur = ""
                elif ch == ' ' and not in_brace:
                    if cur: paths.append(cur); cur = ""
                else:
                    cur += ch
            if cur:
                paths.append(cur)
            for p in paths:
                try:
                    content = Path(p).read_text(encoding="utf-8", errors="replace")
                    if url_text.get("1.0", "end").strip():
                        url_text.insert("end", "\n")
                    url_text.insert("end", content)
                except OSError:
                    pass

        url_text.dnd_bind("<<Drop>>", _on_drop)
    except (ImportError, AttributeError):
        # tkinterdnd2 not installed (or wrong Tk binding) — fall back to the
        # "Load from file..." button below. This is best-effort, not required.
        pass

    # #6: drag-and-drop placeholder (no-op without tkdnd) — see above.
    # We use the basic Tk approach (no tkdnd dep): hint the user via the label and
    # provide a "Load from file..." button as a reliable fallback.
    btn_row = ttk.Frame(body)
    btn_row.pack(fill="x")
    ttk.Button(btn_row, text="Load from file...",
               command=lambda: _mt_load_file(url_text)).pack(side="left")
    ttk.Button(btn_row, text="Clear",
               command=lambda: url_text.delete("1.0", "end")).pack(side="left", padx=(6, 0))
    # Capture a reference to the start button so we can disable it while the
    # worker runs (prevents double-clicks spawning duplicate threads).
    start_btn = ttk.Button(btn_row, text="Start scanning queue",
                           style="Accent.TButton")
    start_btn.configure(command=lambda: _mt_start(app, win, url_text, results_tv, start_btn))
    start_btn.pack(side="right")

    ttk.Separator(body, orient="horizontal").pack(fill="x", pady=(8, 6))
    ttk.Label(body, text="Results:", foreground=MUTED).pack(anchor="w")
    results_tv = ttk.Treeview(body, columns=("score", "delta", "crit", "high", "med"),
                              show="tree headings", height=10)
    results_tv.heading("#0", text="URL")
    results_tv.heading("score", text="Score")
    results_tv.heading("delta", text="Δ vs last")
    results_tv.heading("crit", text="Crit")
    results_tv.heading("high", text="High")
    results_tv.heading("med", text="Med")
    results_tv.column("#0", width=320, anchor="w")
    results_tv.column("score", width=60, anchor="center")
    results_tv.column("delta", width=70, anchor="center")
    results_tv.column("crit", width=50, anchor="center")
    results_tv.column("high", width=50, anchor="center")
    results_tv.column("med", width=50, anchor="center")
    results_tv.pack(fill="both", expand=True, pady=(4, 0))
    # C6: Compare selected — opens a side-by-side compare window
    results_tv.configure(selectmode="extended")
    ttk.Label(body, text="Tip: Ctrl-click rows then click Compare to see them side-by-side.",
              foreground=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

    def _compare_selected():
        sel = results_tv.selection()
        if len(sel) < 2:
            messagebox.showinfo("Compare", "Select 2 or more rows to compare.")
            return
        from . import history as _h
        selected_rows = []
        for iid in sel:
            url = results_tv.item(iid, "text")
            snapshot = _h.previous_report_path(url)
            selected_rows.append({"url": url, "snapshot_path": str(snapshot) if snapshot else None})
        open_compare(app, selected_rows)
    ttk.Button(body, text="Compare selected", command=_compare_selected).pack(anchor="e", pady=(6, 0))

    win.update_idletasks()
    x = app.root.winfo_rootx() + 80
    y = app.root.winfo_rooty() + 80
    win.geometry(f"+{x}+{y}")


def _mt_load_file(url_text: tk.Text) -> None:
    p = filedialog.askopenfilename(filetypes=[("URL list", "*.txt"), ("All files", "*.*")])
    if not p:
        return
    try:
        content = Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        messagebox.showerror("Load file", f"Failed: {e}")
        return
    if url_text.get("1.0", "end").strip():
        url_text.insert("end", "\n")
    url_text.insert("end", content)


def _mt_start(app, win, url_text: tk.Text, results_tv: ttk.Treeview,
              start_btn=None) -> None:
    """Start scanning each URL in turn (background thread).

    Disables `start_btn` for the duration of the worker so a second click
    can't spawn a parallel scan worker against the same queue (previously
    double-clicking produced duplicate rows in the Treeview).
    """
    raw = url_text.get("1.0", "end").strip()
    urls = [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not urls:
        messagebox.showinfo("Multi-target", "No URLs to scan.")
        return
    # Clear any prior rows
    for c in results_tv.get_children():
        results_tv.delete(c)
    if start_btn is not None:
        start_btn.configure(state="disabled")
    import threading
    t = threading.Thread(target=_mt_worker, args=(app, urls, results_tv, start_btn), daemon=True)
    t.start()


def _mt_worker(app, urls: list[str], results_tv: ttk.Treeview, start_btn=None) -> None:
    """Background scan loop. Updates the Treeview via after() per URL."""
    import asyncio
    from .scanner import scan as _scan
    from . import history as _h
    for url in urls:
        try:
            report = asyncio.run(_scan(url, timeout=15.0, aggressive=False, sequential=True))
        except Exception as e:  # noqa: BLE001
            app.root.after(0, lambda u=url, m=str(e): results_tv.insert("", "end", text=u, values=("ERR", m[:20], "", "", "")))
            continue
        # Compute delta vs last snapshot
        prior_path = _h.previous_report_path(url)
        delta = ""
        if prior_path and prior_path.exists():
            try:
                prior = json.loads(prior_path.read_text(encoding="utf-8"))
                if "risk_score" in prior:
                    d = report.risk_score - int(prior["risk_score"])
                    delta = f"{'+' if d > 0 else ''}{d}"
            except (OSError, json.JSONDecodeError, ValueError):
                pass
        # Save snapshot for future deltas
        try:
            from .reporters import json_out as _jr
            _h.save_report_snapshot(url, _jr.render(report))
            _h.push_url(url)
        except Exception:  # noqa: BLE001
            pass
        s = report.summary
        app.root.after(0, lambda u=url, r=report, d=delta, s=s: results_tv.insert(
            "", "end", text=u, values=(r.risk_score, d, s.get("critical", 0), s.get("high", 0), s.get("medium", 0))
        ))
    # Re-enable the start button on the main thread once the worker finishes.
    if start_btn is not None:
        try:
            app.root.after(0, lambda: start_btn.configure(state="normal"))
        except Exception:  # noqa: BLE001
            pass


# ----------------------- #2 Schedule recurring scan -----------------------

def open_schedule(app) -> None:
    """Register a Windows Task Scheduler entry to run wpsecscan.exe periodically."""
    if hasattr(app, "_sched_win") and app._sched_win is not None and app._sched_win.winfo_exists():
        app._sched_win.lift()
        app._sched_win.focus_force()
        return
    win = tk.Toplevel(app.root)
    app._sched_win = win
    win.title("Schedule recurring scan")
    win.configure(bg=BG)
    win.transient(app.root)
    win.bind("<Destroy>", lambda _e, w=win: setattr(app, "_sched_win", None) if getattr(app, "_sched_win", None) is w else None)
    win.bind("<Escape>", lambda _e: win.destroy())  # #6

    body = ttk.Frame(win, padding=14)
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="Register a Windows Task Scheduler job", font=("Segoe UI", 10, "bold")).grid(
        row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
    ttk.Label(body, text="URL:").grid(row=1, column=0, sticky="w", padx=(0, 8))
    url_var = tk.StringVar(value=app.url_var.get())
    ttk.Entry(body, textvariable=url_var, width=42).grid(row=1, column=1, columnspan=2, sticky="ew")
    ttk.Label(body, text="Frequency:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    freq_var = tk.StringVar(value="DAILY")
    ttk.OptionMenu(body, freq_var, "DAILY", "DAILY", "WEEKLY", "MONTHLY").grid(row=2, column=1, sticky="w", pady=(6, 0))
    ttk.Label(body, text="Time of day (HH:MM):").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    time_var = tk.StringVar(value="03:30")
    ttk.Entry(body, textvariable=time_var, width=8).grid(row=3, column=1, sticky="w", pady=(6, 0))
    ttk.Label(body, text="Output folder:").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
    out_var = tk.StringVar(value=str(Path.home() / ".wpsecscan" / "scheduled"))
    ttk.Entry(body, textvariable=out_var, width=42).grid(row=4, column=1, columnspan=2, sticky="ew", pady=(6, 0))

    info = ttk.Label(body, text=(
        "This uses schtasks.exe to create a 'WPSecScan_<host>' task that runs the bundled wpsecscan.exe\n"
        "at the chosen interval. Outputs are written to the folder above. To remove it later:\n"
        "  schtasks /Delete /TN WPSecScan_<host>"
    ), foreground=MUTED, justify="left")
    info.grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))

    btn_row = ttk.Frame(body)
    btn_row.grid(row=6, column=0, columnspan=3, sticky="e", pady=(12, 0))
    ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="right", padx=(6, 0))
    ttk.Button(btn_row, text="Register", style="Accent.TButton",
               command=lambda: _register_scheduled(url_var.get(), freq_var.get(), time_var.get(), out_var.get(), win)).pack(side="right")


def _register_scheduled(url: str, freq: str, time_str: str, out_dir: str, win) -> None:
    import re
    import subprocess
    import sys as _sys
    from urllib.parse import urlparse
    url = (url or "").strip()
    if not url:
        messagebox.showerror("Schedule", "URL is required.")
        return
    # Strict URL whitelist — only http(s)://hostname/path with no shell-meta chars.
    # Defense-in-depth: even though schtasks /TR isn't shell-evaluated, we never
    # want to embed an attacker-controlled URL anywhere risky.
    if not re.match(r"^https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[A-Za-z0-9._\-/~%?&=+#]*)?$", url):
        messagebox.showerror("Schedule",
            "URL must be http://hostname/... with only safe characters.\n"
            "Shell metacharacters and quotes are rejected.")
        return
    if not out_dir:
        messagebox.showerror("Schedule", "Output folder is required.")
        return
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    host = (urlparse(url).hostname or "site").replace(".", "_")
    # Sanitize task_name (schtasks doesn't accept arbitrary chars)
    task_name = re.sub(r"[^A-Za-z0-9_-]", "_", f"WPSecScan_{host}")[:120]
    # Find the wpsecscan executable (running as the bundled GUI exe, sibling exe is wpsecscan.exe)
    cand: Path
    if getattr(_sys, "frozen", False):
        cand = Path(_sys.executable).parent / "wpsecscan.exe"
    else:
        cand = Path(_sys.executable)  # python.exe fallback (dev)
    if not cand.exists():
        messagebox.showerror("Schedule", f"Couldn't find wpsecscan.exe next to this binary.\nExpected at: {cand}")
        return
    # schtasks /TR takes one quoted string. We've validated url + out_dir are safe;
    # build with simple double-quoting (no embedded quotes possible after the regex).
    cmd_line = f'"{cand}" "{url}" --out "{out_dir}" --json-only --no-console'
    args = [
        "schtasks", "/Create", "/F", "/TN", task_name,
        "/TR", cmd_line, "/SC", freq, "/ST", time_str,
    ]
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        messagebox.showerror("Schedule", f"schtasks failed: {e}")
        return
    if result.returncode != 0:
        messagebox.showerror("Schedule", f"schtasks returned {result.returncode}:\n{result.stderr or result.stdout}")
        return
    messagebox.showinfo(
        "Schedule",
        f"✓ Task '{task_name}' registered.\n\n"
        f"Runs {freq} at {time_str}.\nOutput: {out_dir}\n\n"
        f"To remove: schtasks /Delete /TN {task_name} /F"
    )
    win.destroy()


# ----------------------- #11 Trend sparkline -----------------------

def open_trend(app) -> None:
    """Show risk-score-over-time for the current URL using snapshots in ~/.wpsecscan/reports/.

    Limitation: snapshot files are overwritten per URL, so we only have the most-recent.
    Real trends need history retention — for now, the window shows the latest score and a
    note that retention is a future feature, but reads any backup snapshots that exist.
    """
    url = (app.url_var.get() or "").strip()
    if not url:
        messagebox.showinfo("Trend", "Enter a URL first.")
        return
    win = tk.Toplevel(app.root)
    win.title(f"Risk trend — {url}")
    win.configure(bg=BG)
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())  # #6
    body = ttk.Frame(win, padding=14)
    body.pack(fill="both", expand=True)

    # Look for snapshot files matching this URL. history.save_report_snapshot
    # writes exactly `{safe}.json`; the previous `*{safe}*.json` glob was
    # over-broad and matched sibling sites (e.g. safe='test.com' also matched
    # 'bigtest.com.json'). Match the exact file plus any timestamped variants
    # the codebase might add later (`{safe}-{date}.json`).
    # Only use the timestamped snapshots — including the canonical `{safe}.json`
    # would duplicate the latest data point in the sparkline (it's just an alias
    # for the most recent timestamped file).
    import glob as _glob
    from . import history as _h
    safe = _h._safe_filename(url)
    reports_dir = Path.home() / ".wpsecscan" / "reports"
    snapshots: list[tuple[str, int]] = []
    if reports_dir.exists():
        candidates = list(reports_dir.glob(f"{_glob.escape(safe)}-*.json"))
        for p in sorted(candidates):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                snapshots.append((d.get("scanned_at", p.stem), int(d.get("risk_score", 0))))
            except (OSError, json.JSONDecodeError, ValueError):
                continue

    if not snapshots:
        ttk.Label(body, text=f"No prior scans for {url}.", foreground=MUTED).pack(anchor="w")
    else:
        ttk.Label(body, text=f"Risk score trend ({len(snapshots)} scan(s))",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        # ASCII sparkline (no extra dependency)
        scores = [s for _t, s in snapshots]
        spark = _ascii_spark(scores)
        ttk.Label(body, text=spark, font=("Consolas", 14), foreground="#79c0ff").pack(anchor="w", pady=(0, 8))
        # Tabular detail
        for ts, sc in snapshots[-10:]:
            ttk.Label(body, text=f"  {ts}    score {sc}/100", foreground=FG).pack(anchor="w")
    ttk.Button(body, text="Close", command=win.destroy).pack(anchor="e", pady=(12, 0))


def _ascii_spark(values: list[int]) -> str:
    """Tiny Unicode block sparkline."""
    if not values:
        return ""
    BLOCKS = "▁▂▃▄▅▆▇█"
    lo, hi = min(values), max(values)
    span = max(1, hi - lo)
    out = []
    for v in values:
        idx = int(((v - lo) / span) * (len(BLOCKS) - 1))
        out.append(BLOCKS[idx])
    return "".join(out)


# ----------------------- C1 Per-check disable grid -----------------------

def _disabled_checks_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "disabled_checks.json"


def load_disabled_checks() -> set[str]:
    """C1: read the set of check_ids the user has disabled (persists across runs)."""
    p = _disabled_checks_path()
    if not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text(encoding="utf-8")) or [])
    except (OSError, ValueError):
        return set()


def save_disabled_checks(disabled: set[str]) -> None:
    try:
        _disabled_checks_path().write_text(json.dumps(sorted(disabled)), encoding="utf-8")
    except OSError:
        pass


def open_disable_grid(app) -> None:
    """C1: scrollable per-check enable/disable grid. Persists to ~/.wpsecscan/disabled_checks.json."""
    if hasattr(app, "_disable_grid_win") and app._disable_grid_win is not None and app._disable_grid_win.winfo_exists():
        app._disable_grid_win.lift()
        app._disable_grid_win.focus_force()
        return
    from .checks import ALL_CHECKS
    disabled = load_disabled_checks()
    win = tk.Toplevel(app.root)
    app._disable_grid_win = win
    win.title("Enable / disable checks")
    win.configure(bg=BG)
    win.geometry("560x600")
    win.transient(app.root)
    win.bind("<Destroy>", lambda _e, w=win: setattr(app, "_disable_grid_win", None) if getattr(app, "_disable_grid_win", None) is w else None)
    win.bind("<Escape>", lambda _e: win.destroy())

    header = ttk.Frame(win, padding=(12, 10, 12, 6))
    header.pack(fill="x")
    ttk.Label(header, text="Uncheck a check to skip it in future scans.",
              foreground=MUTED).pack(anchor="w")

    body = ttk.Frame(win, padding=(0, 0, 0, 0))
    body.pack(fill="both", expand=True)

    canvas = tk.Canvas(body, bg=BG, highlightthickness=0)
    scrollbar = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
    inner = ttk.Frame(canvas)
    inner_id = canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    vars_by_cid: dict[str, tk.BooleanVar] = {}
    for cid, cname, _fn, _agg in ALL_CHECKS:
        v = tk.BooleanVar(value=(cid not in disabled))
        vars_by_cid[cid] = v
        row = ttk.Frame(inner, padding=(12, 2, 12, 2))
        row.pack(fill="x", anchor="w")
        ttk.Checkbutton(row, text=cname, variable=v).pack(side="left")
        ttk.Label(row, text=f"({cid})", foreground=MUTED, font=("Segoe UI", 8)).pack(side="left", padx=(8, 0))

    def _update_scroll(_e=None):
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfigure(inner_id, width=canvas.winfo_width())
    inner.bind("<Configure>", _update_scroll)
    canvas.bind("<Configure>", _update_scroll)

    btn_row = ttk.Frame(win, padding=(12, 6, 12, 12))
    btn_row.pack(fill="x")

    def _save_and_close():
        new_disabled = {cid for cid, v in vars_by_cid.items() if not v.get()}
        save_disabled_checks(new_disabled)
        win.destroy()
    ttk.Button(btn_row, text="Save", command=_save_and_close, style="Accent.TButton").pack(side="right")
    ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="right", padx=(0, 6))

    def _toggle_all(value: bool):
        for v in vars_by_cid.values():
            v.set(value)
    ttk.Button(btn_row, text="Enable all", command=lambda: _toggle_all(True)).pack(side="left")
    ttk.Button(btn_row, text="Disable all", command=lambda: _toggle_all(False)).pack(side="left", padx=(6, 0))


# ----------------------- C3 Search across scan history -----------------------

def open_history_search(app) -> None:
    """C3: search every saved JSON report in ~/.wpsecscan/reports/."""
    if hasattr(app, "_hs_win") and app._hs_win is not None and app._hs_win.winfo_exists():
        app._hs_win.lift()
        return
    win = tk.Toplevel(app.root)
    app._hs_win = win
    win.title("Search scan history")
    win.configure(bg=BG)
    win.geometry("900x600")
    win.transient(app.root)
    win.bind("<Destroy>", lambda _e, w=win: setattr(app, "_hs_win", None) if getattr(app, "_hs_win", None) is w else None)
    win.bind("<Escape>", lambda _e: win.destroy())

    top = ttk.Frame(win, padding=(12, 10, 12, 6))
    top.pack(fill="x")
    ttk.Label(top, text="Find findings across all scans you've ever run:").pack(side="left")
    query_var = tk.StringVar(value="")
    entry = ttk.Entry(top, textvariable=query_var, width=50)
    entry.pack(side="left", padx=(8, 0))
    entry.focus_set()

    results_tv = ttk.Treeview(win, columns=("severity", "url", "title", "date"),
                              show="headings", height=22)
    results_tv.heading("severity", text="Sev")
    results_tv.heading("url", text="URL")
    results_tv.heading("title", text="Finding")
    results_tv.heading("date", text="Scanned")
    results_tv.column("severity", width=80, anchor="center")
    results_tv.column("url", width=260, anchor="w")
    results_tv.column("title", width=420, anchor="w")
    results_tv.column("date", width=120, anchor="center")
    results_tv.pack(fill="both", expand=True, padx=12, pady=(6, 12))

    def _do_search(*_args):
        q = query_var.get().strip().lower()
        for c in results_tv.get_children():
            results_tv.delete(c)
        if not q:
            return
        reports_dir = Path.home() / ".wpsecscan" / "reports"
        if not reports_dir.exists():
            return
        for jp in sorted(reports_dir.glob("*.json")):
            try:
                d = json.loads(jp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            url = d.get("target", "?")
            scanned = (d.get("scanned_at") or "")[:10]
            for r in d.get("results", []) or []:
                for f in r.get("findings", []) or []:
                    blob = (f.get("title", "") + " " + f.get("evidence", "") + " "
                            + r.get("check_id", "")).lower()
                    if q in blob:
                        results_tv.insert("", "end",
                                          values=(f.get("severity", "?").upper(),
                                                  url, f.get("title", "")[:120], scanned))

    entry.bind("<KeyRelease>", _do_search)
    query_var.trace_add("write", lambda *_: _do_search())


# ----------------------- C6 Multi-target compare side-by-side -----------------------

def open_compare(app, selected_rows: list[dict]) -> None:
    """C6: column-wise side-by-side comparison of 3+ scan reports."""
    if not selected_rows:
        messagebox.showinfo("Compare", "No rows selected.")
        return
    win = tk.Toplevel(app.root)
    win.title(f"Compare {len(selected_rows)} sites")
    win.configure(bg=BG)
    win.geometry("1100x650")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=10)
    body.pack(fill="both", expand=True)

    # Build a row-by-row table: rows are check_ids, columns are sites.
    # Each cell shows the worst severity (or ✓ for clean / — for not-run).
    all_check_ids: set[str] = set()
    site_data: list[tuple[str, dict]] = []  # (url, {check_id: worst-sev})
    for row in selected_rows:
        url = row.get("url", "?")
        path = row.get("snapshot_path")
        if path is None or not Path(path).exists():
            continue
        try:
            d = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        per_check: dict[str, str] = {}
        for r in d.get("results", []) or []:
            cid = r.get("check_id", "?")
            all_check_ids.add(cid)
            findings = r.get("findings", []) or []
            sevs = [f.get("severity", "info") for f in findings]
            order = ["critical", "high", "medium", "low", "info"]
            worst = next((s for s in order if s in sevs), "—")
            per_check[cid] = worst
        site_data.append((url, per_check))

    if not site_data:
        ttk.Label(body, text="No snapshots available for the selected rows yet.",
                  foreground=MUTED).pack(anchor="w")
        return

    # Treeview with one column per site
    cols = tuple(f"site{i}" for i in range(len(site_data)))
    tv = ttk.Treeview(body, columns=cols, show="tree headings", height=30)
    tv.heading("#0", text="Check")
    tv.column("#0", width=240, anchor="w")
    for i, (url, _data) in enumerate(site_data):
        tv.heading(cols[i], text=url[:40])
        tv.column(cols[i], width=120, anchor="center")
    tv.pack(fill="both", expand=True)
    for cid in sorted(all_check_ids):
        row_vals = []
        for _url, data in site_data:
            sev = data.get(cid, "—")
            row_vals.append(sev.upper() if sev != "—" else "—")
        tv.insert("", "end", text=cid, values=tuple(row_vals))


# ----------------------- E3 Interactive playbook walker -----------------------

def open_playbook_walker(app, finding_info: dict) -> None:
    """E3: step through a playbook one tool at a time with a progress strip.

    finding_info = {"check_id": "...", "check_name": "...", "target": "..."}
    """
    cid = finding_info.get("check_id", "")
    target = finding_info.get("target") or (app.url_var.get() or "")
    from . import playbook as _pb
    raw = _pb.get_playbook(cid)
    if not raw:
        messagebox.showinfo("Walker",
                            f"No exploit playbook for check_id={cid!r}.")
        return
    pb = _pb.substitute(raw, target)
    buckets = _pb.ordered_buckets(pb)
    if not buckets:
        messagebox.showinfo("Walker", "Playbook has no commands to walk.")
        return

    win = tk.Toplevel(app.root)
    win.title(f"Exploit playbook walker - {finding_info.get('check_name', cid)}")
    win.configure(bg=BG)
    win.geometry("820x560")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=14)
    body.pack(fill="both", expand=True)

    step_var = tk.IntVar(value=0)
    total = len(buckets)

    header = ttk.Label(body, text="", font=("Segoe UI", 12, "bold"), foreground="#79c0ff")
    header.pack(anchor="w")

    progress = ttk.Progressbar(body, mode="determinate", maximum=total)
    progress.pack(fill="x", pady=(8, 12))

    text_frame = ttk.Frame(body)
    text_frame.pack(fill="both", expand=True)
    txt = tk.Text(text_frame, wrap="word", font=("Consolas", 10),
                  bg=PANEL, fg=FG, insertbackground=FG, relief="flat",
                  padx=10, pady=10)
    sb = ttk.Scrollbar(text_frame, orient="vertical", command=txt.yview)
    txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    txt.pack(side="left", fill="both", expand=True)

    nav = ttk.Frame(body)
    nav.pack(fill="x", pady=(12, 0))
    back_btn = ttk.Button(nav, text="< Back")
    next_btn = ttk.Button(nav, text="Next >")
    copy_btn = ttk.Button(nav, text="Copy this step")
    close_btn = ttk.Button(nav, text="Close", command=win.destroy)
    back_btn.pack(side="left")
    next_btn.pack(side="left", padx=(8, 0))
    copy_btn.pack(side="left", padx=(8, 0))
    close_btn.pack(side="right")

    def _show(i: int) -> None:
        i = max(0, min(total - 1, i))
        step_var.set(i)
        _field, label, content = buckets[i]
        header.config(text=f"Step {i+1} of {total} - {label}")
        progress["value"] = i + 1
        txt.config(state="normal")
        txt.delete("1.0", "end")
        if isinstance(content, list):
            txt.insert("1.0", "\n\n".join(str(c) for c in content))
        else:
            txt.insert("1.0", str(content))
        txt.config(state="disabled")
        back_btn.config(state=("disabled" if i == 0 else "normal"))
        next_btn.config(state=("disabled" if i == total - 1 else "normal"))

    def _copy() -> None:
        _field, _label, content = buckets[step_var.get()]
        text = "\n\n".join(str(c) for c in content) if isinstance(content, list) else str(content)
        try:
            win.clipboard_clear()
            win.clipboard_append(text)
        except tk.TclError:
            pass

    back_btn.config(command=lambda: _show(step_var.get() - 1))
    next_btn.config(command=lambda: _show(step_var.get() + 1))
    copy_btn.config(command=_copy)
    win.bind("<Right>", lambda _e: _show(step_var.get() + 1))
    win.bind("<Left>", lambda _e: _show(step_var.get() - 1))

    _show(0)


# ----------------------- E7 Findings drill-down by tag -----------------------

def open_drill_by_tag(app) -> None:
    """E7: pick an OWASP / ATT&CK / CWE / D3FEND tag, list every historical
    finding that touched a check carrying that tag."""
    from . import history as _h
    from . import tags as _t

    tags_map = _t._load() or {}

    owasp_set: set[str] = set()
    attack_set: set[str] = set()
    cwe_set: set[str] = set()
    d3fend_set: set[str] = set()
    for _cid, meta in tags_map.items():
        if isinstance(meta, dict):
            v = meta.get("owasp")
            if v: owasp_set.add(v)
            v = meta.get("attack")
            if v: attack_set.add(v)
            v = meta.get("cwe")
            if v: cwe_set.add(v)
            v = meta.get("d3fend")
            if v: d3fend_set.add(v)

    win = tk.Toplevel(app.root)
    win.title("Drill-down by tag")
    win.configure(bg=BG)
    win.geometry("900x600")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=12)
    body.pack(fill="both", expand=True)

    picker = ttk.Frame(body)
    picker.pack(fill="x")

    ttk.Label(picker, text="Tag type:").grid(row=0, column=0, padx=(0, 6))
    tag_kind = tk.StringVar(value="owasp")
    kind_box = ttk.Combobox(picker, textvariable=tag_kind, state="readonly", width=10,
                            values=("owasp", "attack", "cwe", "d3fend"))
    kind_box.grid(row=0, column=1)

    ttk.Label(picker, text="Value:").grid(row=0, column=2, padx=(12, 6))
    tag_value = tk.StringVar()
    value_box = ttk.Combobox(picker, textvariable=tag_value, width=40)
    value_box.grid(row=0, column=3, sticky="ew")

    def _refresh_values(*_a) -> None:
        kind = tag_kind.get()
        choices = {"owasp": owasp_set, "attack": attack_set,
                   "cwe": cwe_set, "d3fend": d3fend_set}[kind]
        value_box["values"] = tuple(sorted(choices))
        if value_box["values"]:
            tag_value.set(value_box["values"][0])
        else:
            tag_value.set("")
    tag_kind.trace_add("write", lambda *_a: _refresh_values())
    _refresh_values()

    cols = ("when", "url", "check", "severity", "title")
    tv = ttk.Treeview(body, columns=cols, show="headings", height=22)
    for c, w in zip(cols, (140, 220, 130, 80, 380)):
        tv.heading(c, text=c.capitalize())
        tv.column(c, width=w, anchor="w")
    tv.pack(fill="both", expand=True, pady=(10, 8))

    info_lbl = ttk.Label(body, text="", foreground=MUTED)
    info_lbl.pack(anchor="w")

    def _run() -> None:
        tv.delete(*tv.get_children())
        kind, val = tag_kind.get(), (tag_value.get() or "").strip()
        if not val:
            info_lbl.config(text="Pick a value.")
            return
        matching_cids = {
            cid for cid, meta in tags_map.items()
            if isinstance(meta, dict) and meta.get(kind) == val
        }
        if not matching_cids:
            info_lbl.config(text="No checks carry this tag.")
            return
        reports_dir = Path(_h._home()) / "reports"
        count = 0
        if reports_dir.exists():
            for p in sorted(reports_dir.glob("*.json")):
                try:
                    d = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                when = d.get("scanned_at", p.stem)
                url = d.get("target", "?")
                for r in d.get("results", []) or []:
                    if r.get("check_id") not in matching_cids:
                        continue
                    for f in r.get("findings", []) or []:
                        tv.insert("", "end", values=(
                            when[:19], url[:60], r.get("check_id", "?"),
                            (f.get("severity", "") or "").upper(),
                            (f.get("title", "") or "")[:200],
                        ))
                        count += 1
        info_lbl.config(text=f"{count} historical finding(s) under {kind}={val}.")

    btns = ttk.Frame(body)
    btns.pack(fill="x")
    ttk.Button(btns, text="Run", command=_run).pack(side="left")
    ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")


# ----------------------- E8 Multi-URL trend graph -----------------------

def open_multi_trend(app) -> None:
    """E8: overlay risk-score sparklines for multiple URLs in one window."""
    from . import history as _h

    win = tk.Toplevel(app.root)
    win.title("Multi-URL risk trend")
    win.configure(bg=BG)
    win.geometry("900x600")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=12)
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="Risk-score trend across all URLs with >=2 snapshots",
              font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 8))

    reports_dir = Path(_h._home()) / "reports"
    by_url: dict[str, list[tuple[str, int]]] = {}
    if reports_dir.exists():
        for p in sorted(reports_dir.glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            url = d.get("target", "?")
            by_url.setdefault(url, []).append((d.get("scanned_at", p.stem),
                                               int(d.get("risk_score", 0))))
    multi = {url: pts for url, pts in by_url.items() if len(pts) >= 2}

    if not multi:
        ttk.Label(body, text="No URLs have multiple snapshots yet. "
                  "Run a scan twice against the same URL to see a trend.",
                  foreground=MUTED, wraplength=820).pack(anchor="w")
        return

    all_scores = [s for pts in multi.values() for _t, s in pts]
    lo = max(0, min(all_scores) - 5)
    hi = min(100, max(all_scores) + 5)
    span = max(1, hi - lo)

    canvas = tk.Canvas(body, bg=PANEL, highlightthickness=0, height=380)
    canvas.pack(fill="both", expand=True)

    legend = ttk.Frame(body)
    legend.pack(fill="x", pady=(8, 0))

    palette = ("#79c0ff", "#f0c674", "#6cc474", "#ff8a85", "#c47700",
               "#b392f0", "#56d4dd", "#f87171", "#a3e635", "#fb923c")

    def _redraw(_e=None) -> None:
        canvas.delete("all")
        W = max(canvas.winfo_width(), 600)
        H = max(canvas.winfo_height(), 300)
        pad_l, pad_r, pad_t, pad_b = 50, 20, 16, 36

        plot_w = W - pad_l - pad_r
        plot_h = H - pad_t - pad_b

        for grid in (0, 25, 50, 75, 100):
            if not (lo <= grid <= hi):
                continue
            yy = pad_t + plot_h * (1 - (grid - lo) / span)
            canvas.create_line(pad_l, yy, W - pad_r, yy, fill="#30363d")
            canvas.create_text(pad_l - 6, yy, anchor="e", fill=MUTED,
                               text=str(grid), font=("Segoe UI", 9))

        for i, (url, pts) in enumerate(sorted(multi.items())):
            color = palette[i % len(palette)]
            n = len(pts)
            for j in range(n - 1):
                x1 = pad_l + plot_w * (j / max(1, n - 1))
                x2 = pad_l + plot_w * ((j + 1) / max(1, n - 1))
                y1 = pad_t + plot_h * (1 - (pts[j][1] - lo) / span)
                y2 = pad_t + plot_h * (1 - (pts[j + 1][1] - lo) / span)
                canvas.create_line(x1, y1, x2, y2, fill=color, width=2)
            for j, (_ts, sc) in enumerate(pts):
                cx = pad_l + plot_w * (j / max(1, n - 1))
                cy = pad_t + plot_h * (1 - (sc - lo) / span)
                canvas.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill=color, outline=color)

        canvas.create_text(pad_l, H - 10, anchor="w", text="oldest scan",
                           fill=MUTED, font=("Segoe UI", 8))
        canvas.create_text(W - pad_r, H - 10, anchor="e", text="newest scan",
                           fill=MUTED, font=("Segoe UI", 8))
    canvas.bind("<Configure>", _redraw)

    for i, url in enumerate(sorted(multi)):
        color = palette[i % len(palette)]
        sw = tk.Frame(legend, bg=color, width=12, height=12)
        sw.pack_propagate(False)
        sw.pack(side="left", padx=(0, 4))
        ttk.Label(legend, text=f"{url[:50]} ({len(multi[url])} pts)").pack(side="left", padx=(0, 12))


# ----------------------- E10 Tutorial mode -----------------------

def _tutorial_seen_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / ".tutorial_seen"


def has_seen_tutorial() -> bool:
    return _tutorial_seen_path().exists()


def mark_tutorial_seen() -> None:
    try:
        _tutorial_seen_path().write_text("1", encoding="utf-8")
    except OSError:
        pass


def open_tutorial(app) -> None:
    """E10: 5-step guided tour shown on first run (or via Help menu)."""
    steps = [
        ("1 of 5 - Enter a URL",
         "Paste the WordPress site URL into the URL field at the top.\n\n"
         "Examples: https://example.com or https://blog.example.com/.\n"
         "The scanner auto-prepends https:// if you omit it."),
        ("2 of 5 - Pick a scan profile",
         "Use File -> Profiles to choose preset settings:\n\n"
         "- Quick (passive only, ~20s)\n"
         "- Standard (default; passive + a few active probes)\n"
         "- Aggressive (active CVE confirmation, SQLi, SSTI - get written permission first)\n"
         "- Authenticated (admin-cookie probes, REST as a user)"),
        ("3 of 5 - Press Scan (or F5)",
         "Findings stream in as each check completes.\n\n"
         "Each finding shows severity, evidence, remediation, and a copy-paste "
         "playbook (sqlmap, Metasploit, nuclei...).\n\n"
         "Press Esc to cancel a running scan."),
        ("4 of 5 - Save & share results",
         "After a scan, use:\n\n"
         "- Open HTML: view the full report in your browser\n"
         "- Copy JSON: paste into a ticket\n"
         "- File -> Export all findings as Markdown: for Confluence / GitHub\n\n"
         "Tools -> Show risk trend tracks the score over time."),
        ("5 of 5 - More tools",
         "Tools menu has:\n\n"
         "- Multi-target scan: sweep dozens of URLs in one run\n"
         "- Schedule recurring scan: nightly / weekly automation\n"
         "- Enable / disable checks: per-check toggle grid\n"
         "- Add Windows Defender exclusion: if WPSecScan gets flagged\n\n"
         "You can re-open this tutorial any time via Help -> Tutorial."),
    ]

    win = tk.Toplevel(app.root)
    win.title("Welcome to WPSecScan")
    win.configure(bg=BG)
    win.geometry("520x360")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=18)
    body.pack(fill="both", expand=True)

    title = ttk.Label(body, text="", font=("Segoe UI", 13, "bold"), foreground="#79c0ff")
    title.pack(anchor="w")

    msg = tk.Text(body, wrap="word", height=10, bg=PANEL, fg=FG, relief="flat",
                  padx=10, pady=10, font=("Segoe UI", 10))
    msg.pack(fill="both", expand=True, pady=(8, 12))

    nav = ttk.Frame(body)
    nav.pack(fill="x")
    back_btn = ttk.Button(nav, text="< Back")
    next_btn = ttk.Button(nav, text="Next >")
    skip_btn = ttk.Button(nav, text="Skip tour", command=win.destroy)
    back_btn.pack(side="left")
    next_btn.pack(side="left", padx=(6, 0))
    skip_btn.pack(side="right")

    idx = tk.IntVar(value=0)

    def _show(i: int) -> None:
        i = max(0, min(len(steps) - 1, i))
        idx.set(i)
        t, body_text = steps[i]
        title.config(text=t)
        msg.config(state="normal")
        msg.delete("1.0", "end")
        msg.insert("1.0", body_text)
        msg.config(state="disabled")
        back_btn.config(state=("disabled" if i == 0 else "normal"))
        if i == len(steps) - 1:
            next_btn.config(text="Got it!", command=lambda: (mark_tutorial_seen(), win.destroy()))
        else:
            next_btn.config(text="Next >", command=lambda: _show(idx.get() + 1))

    back_btn.config(command=lambda: _show(idx.get() - 1))
    _show(0)
    win.bind("<Right>", lambda _e: next_btn.invoke())
    win.bind("<Left>", lambda _e: back_btn.invoke())


# ----------------------- E4 helper: launch the diff viewer in browser -----------------------

def open_diff_viewer(app) -> None:
    """E4 GUI helper: write the standalone diff viewer to a temp file and
    open it in the default browser."""
    import tempfile
    import webbrowser
    from .reporters import diff_viewer as _dv
    fp = Path(tempfile.gettempdir()) / "wpsecscan_diff_viewer.html"
    _dv.write(fp)
    webbrowser.open(fp.as_uri())


# ----------------------- F5 Plugin / signature marketplace browser -----------------------

def open_marketplace(app) -> None:
    """F5: browse the static curated drop-in catalogue."""
    from . import marketplace as _mp

    cat = _mp.load_catalogue()
    entries = cat.get("entries") or []

    win = tk.Toplevel(app.root)
    win.title("Drop-in marketplace")
    win.configure(bg=BG)
    win.geometry("900x560")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=12)
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="Community signatures, payload packs, and custom checks",
              font=("Segoe UI", 11, "bold")).pack(anchor="w")
    ttk.Label(body, text="The marketplace shows the source URL only. Inspect each file BEFORE "
              "placing it in your ~/.wpsecscan/ tree — drop-ins run with WPSecScan's privileges.",
              foreground=MUTED, wraplength=860).pack(anchor="w", pady=(0, 10))

    cat_row = ttk.Frame(body)
    cat_row.pack(fill="x")
    ttk.Label(cat_row, text="Filter:").pack(side="left", padx=(0, 6))
    cat_var = tk.StringVar(value="all")
    for label, val in (("All", "all"), ("Signatures", "signature"),
                       ("Payloads", "payload"), ("Plugins (checks)", "plugin")):
        ttk.Radiobutton(cat_row, text=label, value=val, variable=cat_var).pack(side="left", padx=(0, 6))

    cols = ("name", "category", "author", "license", "install_to")
    tv = ttk.Treeview(body, columns=cols, show="headings", height=14)
    for c, w in zip(cols, (220, 90, 130, 90, 320)):
        tv.heading(c, text=c.replace("_", " ").capitalize())
        tv.column(c, width=w, anchor="w")
    tv.pack(fill="both", expand=True, pady=(8, 8))

    summary_lbl = ttk.Label(body, text="", foreground=MUTED, wraplength=860)
    summary_lbl.pack(anchor="w")

    def _populate() -> None:
        tv.delete(*tv.get_children())
        kind = cat_var.get()
        for e in entries:
            if kind != "all" and e.get("category") != kind:
                continue
            tv.insert("", "end", iid=e.get("id", e.get("name", "?")),
                      values=(e.get("name", "?"), e.get("category", "?"),
                              e.get("author", "?"), e.get("license", "?"),
                              e.get("install_to", "?")))

    def _on_select(_e=None) -> None:
        sel = tv.selection()
        if not sel:
            summary_lbl.config(text="")
            return
        e = next((x for x in entries if x.get("id") == sel[0] or x.get("name") == sel[0]), None)
        if not e:
            return
        summary_lbl.config(text=f"{e.get('summary', '')}\nSource: {e.get('source', '')}")

    cat_var.trace_add("write", lambda *_a: _populate())
    tv.bind("<<TreeviewSelect>>", _on_select)
    _populate()

    def _copy_source() -> None:
        sel = tv.selection()
        if not sel:
            return
        e = next((x for x in entries if x.get("id") == sel[0] or x.get("name") == sel[0]), None)
        if e and e.get("source"):
            try:
                win.clipboard_clear()
                win.clipboard_append(e["source"])
            except tk.TclError:
                pass

    def _open_source() -> None:
        sel = tv.selection()
        if not sel:
            return
        e = next((x for x in entries if x.get("id") == sel[0] or x.get("name") == sel[0]), None)
        if e and e.get("source"):
            import webbrowser
            webbrowser.open(e["source"])

    btns = ttk.Frame(body)
    btns.pack(fill="x", pady=(8, 0))
    ttk.Button(btns, text="Copy source URL", command=_copy_source).pack(side="left")
    ttk.Button(btns, text="Open source in browser", command=_open_source).pack(side="left", padx=(8, 0))
    ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")


# ----------------------- O49 Onboarding wizard -----------------------

def open_onboarding_wizard(app) -> None:
    """O49: first-run setup wizard — collects API tokens (HIBP, Wordfence,
    Patchstack, GitHub, VT, AbuseIPDB) and writes them to a per-user
    settings file. All fields are optional; the wizard works even if the
    user skips every step."""
    from . import history as _h

    win = tk.Toplevel(app.root)
    win.title("WPSecScan setup")
    win.configure(bg=BG)
    win.geometry("560x500")
    win.transient(app.root)
    win.bind("<Escape>", lambda _e: win.destroy())

    body = ttk.Frame(win, padding=18)
    body.pack(fill="both", expand=True)

    ttk.Label(body, text="WPSecScan setup", font=("Segoe UI", 14, "bold"),
              foreground="#79c0ff").pack(anchor="w")
    ttk.Label(body, text="Optional API tokens — every field can be left blank.",
              foreground=MUTED).pack(anchor="w", pady=(0, 14))

    tokens = (
        ("wpscan_token", "WPScan API token",
         "wpscan.com — free 25 req/day for plugin/theme CVE lookups"),
        ("patchstack_token", "Patchstack token",
         "patchstack.com — WP-specific CVE feed; free tier available"),
        ("hibp_token", "HaveIBeenPwned key",
         "haveibeenpwned.com — $4/mo; auto-checks discovered user emails"),
        ("vt_token", "VirusTotal key",
         "virustotal.com — free 4 req/min; URL + IP reputation"),
        ("abuseipdb_token", "AbuseIPDB key",
         "abuseipdb.com — free 1000 req/day; IP-reputation lookup"),
        ("github_search_token", "GitHub PAT (public_repo)",
         "github.com/settings/tokens — code-search for leaked secrets"),
    )

    vars_: dict[str, tk.StringVar] = {}
    saved = _load_setup_tokens()
    for key, label, hint in tokens:
        ttk.Label(body, text=label, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 0))
        ttk.Label(body, text=hint, foreground=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
        v = tk.StringVar(value=saved.get(key, ""))
        vars_[key] = v
        ttk.Entry(body, textvariable=v, show="*", width=70).pack(anchor="w", pady=(2, 0))

    btns = ttk.Frame(body)
    btns.pack(fill="x", pady=(16, 0))
    ttk.Button(btns, text="Skip for now", command=win.destroy).pack(side="right")

    def _save_and_close():
        data = {k: v.get().strip() for k, v in vars_.items() if v.get().strip()}
        _save_setup_tokens(data)
        try:
            messagebox.showinfo(APP_NAME,
                                f"Saved {len(data)} token(s) to ~/.wpsecscan/settings.json.")
        except Exception:  # noqa: BLE001
            pass
        win.destroy()

    ttk.Button(btns, text="Save", command=_save_and_close).pack(side="right", padx=(0, 8))


def _setup_tokens_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "settings.json"


def _load_setup_tokens() -> dict:
    p = _setup_tokens_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save_setup_tokens(data: dict) -> None:
    p = _setup_tokens_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            import os
            os.chmod(p, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _wizard_seen_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / ".wizard_seen"


def has_seen_wizard() -> bool:
    return _wizard_seen_path().exists()


def mark_wizard_seen() -> None:
    try:
        _wizard_seen_path().write_text("1", encoding="utf-8")
    except OSError:
        pass
