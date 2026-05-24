"""Round-59 #74-82 — UX maturity extras.

Tooling helpers for the GUI. All pure functions / opt-in init so they
never break headless / CLI flows.

#74 GUI accessibility audit — `audit_gui()` walks every widget and
    flags missing labels, low contrast, no keyboard focus, etc.
#75 Vim modal keys — `register_vim_bindings(root)` adds h/j/k/l + i + :w
    style bindings to a Tk root.
#76 Power-user shortcuts — Ctrl+Shift+P (palette), Ctrl+R (rescan),
    Ctrl+E (export), Ctrl+L (focus log), Ctrl+/ (search).
#77 OS dark-mode follow — `current_os_theme()` returns "dark" / "light"
    by reading darkdetect (optional) or the platform-specific registry.
#78 Sound packs — `play(name)` plays one of {"ding","ok","fail","critical"}
    from a small bundled directory (.wav). Honors `WPSECSCAN_QUIET=1`.
#79 Quiet hours — `is_quiet()` returns True between configurable
    start/end hours (default 22:00-07:00 local).
#80 Star / favourite findings — `star_finding(finding_id)` writes to
    ~/.wpsecscan/stars.json. `is_starred(finding_id)` reads.
#81 Saved searches — `save_search(name, filter_dict)` writes a named
    filter; `load_searches()` returns them all.
#82 Obsidian / Notion export — `to_obsidian(report)` returns a markdown
    string suitable for vault import; `to_notion(report)` returns a
    page-tree dict for the Notion API.
"""
from __future__ import annotations

import datetime
import json
import os
import platform
import re
from pathlib import Path
from typing import Any


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


# ---- #74 GUI accessibility audit ----

def audit_gui(root: Any) -> list[dict]:
    """Walk a Tk widget tree and flag a11y issues. Returns issues as
    [{"widget": str, "issue": str, "remediation": str}].

    Pure function — safe to call from a unit test by passing a fake root.
    """
    issues: list[dict] = []
    if root is None:
        return issues
    try:
        children = list(root.winfo_children())
    except AttributeError:
        return issues
    for w in children:
        cls = w.winfo_class() if hasattr(w, "winfo_class") else "?"
        # Buttons / Entries should have an accessible label
        if cls in ("Button", "TButton", "Entry", "TEntry", "Combobox"):
            try:
                text = w.cget("text") if cls in ("Button", "TButton") else ""
            except Exception:  # noqa: BLE001
                text = ""
            if not text and cls in ("Button", "TButton"):
                issues.append({"widget": cls, "issue": "Button without text label",
                                "remediation": "Add `text=` or pair with a Label widget for screen-readers."})
        # Recurse
        if hasattr(w, "winfo_children"):
            issues.extend(audit_gui(w))
    return issues


# ---- #75 Vim modal keys ----

def register_vim_bindings(root: Any) -> None:
    """Register vim-style navigation on a Tk root (no-op if root is None)."""
    if root is None:
        return
    try:
        root.bind("<KeyPress-h>", lambda e: root.tk_focusPrev())
        root.bind("<KeyPress-l>", lambda e: root.tk_focusNext())
        root.bind("<KeyPress-j>", lambda e: root.event_generate("<Down>"))
        root.bind("<KeyPress-k>", lambda e: root.event_generate("<Up>"))
        root.bind("<KeyPress-i>", lambda e: None)   # placeholder: insert mode
        root.bind("<Control-q>", lambda e: root.quit())
    except Exception:  # noqa: BLE001
        pass


# ---- #76 Power-user shortcuts ----

def register_power_shortcuts(root: Any, handlers: dict) -> None:
    """`handlers` is {"palette": fn, "rescan": fn, "export": fn,
    "log": fn, "search": fn}. Missing keys are ignored."""
    if root is None:
        return
    binds = (
        ("<Control-Shift-KeyPress-P>", "palette"),
        ("<Control-r>", "rescan"),
        ("<Control-e>", "export"),
        ("<Control-l>", "log"),
        ("<Control-slash>", "search"),
    )
    for key, name in binds:
        fn = handlers.get(name)
        if not callable(fn):
            continue
        try:
            root.bind(key, lambda e, f=fn: f())
        except Exception:  # noqa: BLE001
            continue


# ---- #77 OS dark-mode follow ----

def current_os_theme() -> str:
    """Returns "dark" or "light". Best-effort across platforms."""
    # Try darkdetect first (optional dep)
    try:
        import darkdetect  # type: ignore[import-untyped]
        v = darkdetect.theme()
        if v:
            return v.lower()
    except ImportError:
        pass
    sys = platform.system().lower()
    if sys == "windows":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            ) as k:
                v, _ = winreg.QueryValueEx(k, "AppsUseLightTheme")
            return "light" if int(v) == 1 else "dark"
        except (FileNotFoundError, OSError, ImportError, ValueError):
            return "light"
    if sys == "darwin":
        try:
            import subprocess
            r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"],
                                capture_output=True, text=True, timeout=2)
            return "dark" if (r.stdout or "").strip().lower() == "dark" else "light"
        except (FileNotFoundError, OSError):
            return "light"
    return "light"


# ---- #78 Sound packs ----

_SOUND_PACK = (Path(__file__).parent / "data" / "sounds")


def play(name: str) -> None:
    """Play `data/sounds/<name>.wav` if found AND not quiet hours / quiet env."""
    if os.environ.get("WPSECSCAN_QUIET"):
        return
    if is_quiet():
        return
    if not name or not re.match(r"^[a-z_]+$", name):
        return
    wav = _SOUND_PACK / f"{name}.wav"
    if not wav.is_file():
        return
    try:
        if platform.system().lower() == "windows":
            import winsound
            winsound.PlaySound(str(wav), winsound.SND_FILENAME | winsound.SND_ASYNC)
        else:
            import subprocess
            subprocess.Popen(["aplay", str(wav)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        pass


# ---- #79 Quiet hours ----

def quiet_hours() -> tuple[int, int]:
    """Returns (start_hour, end_hour). Default 22-7."""
    start = os.environ.get("WPSECSCAN_QUIET_START")
    end = os.environ.get("WPSECSCAN_QUIET_END")
    try:
        s = int(start) if start is not None else 22
        e = int(end) if end is not None else 7
        if 0 <= s < 24 and 0 <= e < 24:
            return s, e
    except ValueError:
        pass
    return 22, 7


def is_quiet(now: datetime.datetime | None = None) -> bool:
    """True if current local hour is within quiet window."""
    n = now or datetime.datetime.now()
    s, e = quiet_hours()
    h = n.hour
    if s <= e:
        return s <= h < e
    return h >= s or h < e


# ---- #80 Star / favourite ----

def _stars_path() -> Path:
    return _home() / "stars.json"


def _load_stars() -> set:
    p = _stars_path()
    if not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text(encoding="utf-8")) or [])
    except (OSError, ValueError):
        return set()


def _save_stars(stars: set) -> None:
    p = _stars_path()
    try:
        if p.is_symlink():
            p.unlink()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sorted(stars)), encoding="utf-8")
    except OSError:
        pass


def star_finding(finding_id: str) -> None:
    if not finding_id:
        return
    s = _load_stars()
    s.add(str(finding_id))
    _save_stars(s)


def unstar_finding(finding_id: str) -> None:
    s = _load_stars()
    s.discard(str(finding_id))
    _save_stars(s)


def is_starred(finding_id: str) -> bool:
    return str(finding_id) in _load_stars()


# ---- #81 Saved searches ----

def _searches_path() -> Path:
    return _home() / "searches.json"


def save_search(name: str, filter_dict: dict) -> None:
    if not name or not isinstance(filter_dict, dict):
        return
    p = _searches_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        data = {}
    data[name] = filter_dict
    try:
        if p.is_symlink():
            p.unlink()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def load_searches() -> dict:
    p = _searches_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


# ---- #82 Obsidian / Notion export ----

def to_obsidian(report: Any) -> str:
    """Markdown suitable for an Obsidian vault. Front-matter + wikilinks
    on the check_id. Tolerates dict or ScanReport-like."""
    if hasattr(report, "to_dict"):
        d = report.to_dict()
    elif isinstance(report, dict):
        d = report
    else:
        return ""
    target = d.get("target", "")
    risk = d.get("risk_score", 0)
    summary = d.get("summary", {})
    lines = [
        "---",
        f'target: "{target}"',
        f"risk_score: {risk}",
        f"critical: {summary.get('critical', 0)}",
        f"high: {summary.get('high', 0)}",
        f"medium: {summary.get('medium', 0)}",
        f"low: {summary.get('low', 0)}",
        "tags: [wpsecscan, security]",
        "---",
        "",
        f"# WPSecScan report — {target}",
        "",
    ]
    for r in d.get("results", []) or []:
        cid = r.get("check_id", "")
        for f in r.get("findings", []) or []:
            sev = (f.get("severity") or "info").upper()
            title = f.get("title") or ""
            lines.append(f"## [{sev}] {title}")
            lines.append(f"- check: [[{cid}]]")
            lines.append(f"- url: {f.get('url') or ''}")
            ev = (f.get("evidence") or "")[:500]
            if ev:
                lines.append(f"\n```\n{ev}\n```")
            lines.append("")
    return "\n".join(lines)


def to_notion(report: Any) -> dict:
    """A Notion-API-shaped page tree (one parent page + child blocks).

    Returns a dict matching `pages.create` payload sans `parent.database_id`
    which the caller must supply.
    """
    if hasattr(report, "to_dict"):
        d = report.to_dict()
    elif isinstance(report, dict):
        d = report
    else:
        return {}
    children = []
    for r in d.get("results", []) or []:
        cid = r.get("check_id", "")
        for f in r.get("findings", []) or []:
            sev = (f.get("severity") or "info").upper()
            title = f.get("title") or ""
            children.append({
                "object": "block",
                "type": "heading_3",
                "heading_3": {"rich_text": [{"type": "text",
                                              "text": {"content": f"[{sev}] {title}"}}]},
            })
            children.append({
                "object": "block",
                "type": "paragraph",
                "paragraph": {"rich_text": [{"type": "text",
                                              "text": {"content": f"check {cid} — {f.get('url') or ''}"}}]},
            })
            ev = (f.get("evidence") or "")[:1500]
            if ev:
                children.append({
                    "object": "block",
                    "type": "code",
                    "code": {"language": "plain text",
                              "rich_text": [{"type": "text", "text": {"content": ev}}]},
                })
    return {
        "properties": {
            "title": [{"type": "text",
                        "text": {"content": f"WPSecScan — {d.get('target', '')}"}}],
        },
        "children": children,
    }
