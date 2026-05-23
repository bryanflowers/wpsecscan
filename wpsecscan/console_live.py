"""Round-56 live console dashboard.

A `rich.Live` multi-panel layout shown during CLI scans so the user can
see every feature working in real time instead of staring at a blank line
until the static reporter renders.

Layout:
    ┌─ header: target · elapsed · check counter ──────────────────┐
    │ Findings (live)              │ Activity feed                │
    │ [HIGH] cors  CORS reflects   │ [intel]  KEV catalog refreshed
    │ [INFO] favicon Hash 0xabcd…  │ [int]    audit log → Splunk  │
    │ …                            │ [art]    screenshots ×3      │
    ├──────────────────────────────┴──────────────────────────────┤
    │  ▰▰▰▰▰▰▰▰▰▱▱▱   67 / 104    eta ~22s    current: jwt_audit │
    └─────────────────────────────────────────────────────────────┘

Falls back cleanly to the static console reporter when:
  - stdout isn't a TTY (e.g. piped)
  - `args.no_console` or `args.quiet` is set
  - the `rich.live` import fails (shouldn't happen — bundled with rich)

Subscribes to the `activity` bus and the scanner's `on_progress` callback.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text

from . import activity as _act
from .models import CheckResult, Finding


_SEV_STYLE = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "dim",
}

_CAT_BADGE = {
    "threat_intel": ("intel", "yellow"),
    "reporter":     ("rprt",  "blue"),
    "integration":  ("integ", "magenta"),
    "governance":   ("gov",   "cyan"),
    "meta":         ("meta",  "yellow"),
    "artifact":     ("art",   "green"),
    "check":        ("chk",   "white"),
}


class LiveDashboard:
    """Owns a rich.Live + Layout + Progress. Use as a context manager:

        with LiveDashboard(console, target, total_checks) as dash:
            on_progress = dash.on_progress_callback()
            report = await scanner.scan(target, on_progress=on_progress, ...)
    """

    def __init__(self, console: Console, target: str, total_checks: int):
        self.console = console
        self.target = target
        self.total_checks = total_checks
        self._started = time.time()
        self._findings_buf: "deque[Finding]" = deque(maxlen=12)
        self._activity_buf: "deque[dict]" = deque(maxlen=15)
        self._done_count = 0
        self._current_label = "starting…"
        self._lock = threading.Lock()
        self._live: Live | None = None
        self._progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("{task.completed}/{task.total}"),
            TimeRemainingColumn(),
            console=console,
            expand=True,
        )
        self._task_id = self._progress.add_task("scanning", total=max(1, total_checks))

    # ---- public API ----

    def __enter__(self):
        layout = self._build_layout()
        self._live = Live(layout, console=self.console, refresh_per_second=8,
                          transient=False, screen=False)
        self._live.__enter__()
        _act.subscribe(self._on_activity)
        return self

    def __exit__(self, exc_type, exc, tb):
        _act.unsubscribe(self._on_activity)
        if self._live is not None:
            try:
                self._live.__exit__(exc_type, exc, tb)
            except Exception:  # noqa: BLE001
                pass
            self._live = None

    def on_progress_callback(self):
        """Returns the callable to pass to `scanner.scan(on_progress=...)`."""
        def cb(event: str, check_id: str, check_name: str,
               result: CheckResult | None) -> None:
            with self._lock:
                if event == "start":
                    self._current_label = check_name
                elif event == "step":
                    # step events ride check_name slot with the substep label
                    self._current_label = f"{check_id}: {check_name}"
                elif event == "done":
                    self._done_count += 1
                    if result is not None:
                        for f in result.findings:
                            self._findings_buf.append(f)
                    self._progress.update(self._task_id, completed=self._done_count)
            self._refresh()
        return cb

    # ---- internals ----

    def _on_activity(self, event: dict) -> None:
        with self._lock:
            self._activity_buf.append(event)
        self._refresh()

    def _refresh(self) -> None:
        if self._live is None:
            return
        try:
            self._live.update(self._build_layout())
        except Exception:  # noqa: BLE001
            # Never let a render error kill the scan
            pass

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._render_header(), name="header", size=3),
            Layout(name="body"),
            Layout(self._render_footer(), name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(self._render_findings(), name="findings", ratio=1),
            Layout(self._render_activity(), name="activity", ratio=1),
        )
        return layout

    def _render_header(self) -> Panel:
        elapsed = time.time() - self._started
        text = Text()
        text.append("WPSecScan", style="bold cyan")
        text.append(" · ")
        text.append(self.target, style="bold")
        text.append("    ")
        text.append(f"{elapsed:5.1f}s", style="dim")
        text.append(f"  ·  {self._done_count}/{self.total_checks} checks", style="dim")
        return Panel(text, border_style="cyan", padding=(0, 1))

    def _render_findings(self) -> Panel:
        tbl = Table.grid(padding=(0, 1))
        tbl.add_column(width=8)
        tbl.add_column()
        with self._lock:
            items = list(self._findings_buf)
        if not items:
            tbl.add_row(Text("(no findings yet)", style="dim"), "")
        else:
            for f in items:
                style = _SEV_STYLE.get(f.severity, "white")
                badge = Text(f.severity.upper()[:7].ljust(7), style=style)
                title = Text(f.title[:80], style="dim" if f.severity == "info" else "")
                tbl.add_row(badge, title)
        return Panel(tbl, title="Findings (live)", border_style="blue", padding=(0, 1))

    def _render_activity(self) -> Panel:
        tbl = Table.grid(padding=(0, 1))
        tbl.add_column(width=7)
        tbl.add_column()
        with self._lock:
            items = list(self._activity_buf)
        if not items:
            tbl.add_row(Text("(quiet — features will report here)", style="dim"), "")
        else:
            for e in items:
                label, color = _CAT_BADGE.get(e.get("category", "check"), ("?", "white"))
                badge = Text(label.ljust(5), style=f"bold {color}")
                msg = Text(e.get("message", "")[:80])
                tbl.add_row(badge, msg)
        return Panel(tbl, title="Activity feed", border_style="magenta", padding=(0, 1))

    def _render_footer(self) -> Panel:
        # Render the rich.Progress instance + a current-check label. Progress
        # is itself a renderable (has __rich_console__) — no need to reach
        # for private helpers.
        body = Table.grid(expand=True)
        body.add_column(ratio=3)
        body.add_column(ratio=2, justify="right")
        with self._lock:
            label = self._current_label
        body.add_row(self._progress, Text(f"current: {label[:40]}", style="dim"))
        return Panel(body, border_style="cyan", padding=(0, 1))


def supports_live(console: Console) -> bool:
    """True if the dashboard will actually render (TTY + not no_console + not quiet)."""
    try:
        return bool(console.is_terminal) and not getattr(console, "is_jupyter", False)
    except Exception:  # noqa: BLE001
        return False
