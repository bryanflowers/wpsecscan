"""#88-102 GUI polish features in one module.

Provides helpers the existing gui.py imports:
  #88 dark/light theme switch
  #89 drag-drop multi-target file handler
  #90 right-click → CyberChef link builder
  #91 right-click → Shodan link builder
  #92 command palette (Ctrl+P fuzzy menu)
  #93 keyboard shortcut cheat sheet (F1)
  #94 in-app changelog viewer
  #95 system tray icon helper
  #96 desktop notification helper
  #97 battery / activity-pause detection
  #98 color theme variants
  #99 sound-effect helper
  #100 onboarding video link
  #101 achievements / gamification storage
  #102 custom CSS for HTML reports loader
"""
from __future__ import annotations

import json
import os
import platform
import urllib.parse
from pathlib import Path


# ---- #90 CyberChef link ----
def cyberchef_url(value: str, op: str = "Decode_text('UTF-8')") -> str:
    enc = urllib.parse.quote_plus(value)
    recipe = urllib.parse.quote_plus(op)
    return f"https://gchq.github.io/CyberChef/#recipe={recipe}&input={enc}"


# ---- #91 Shodan link ----
def shodan_search_url(host: str) -> str:
    return f"https://www.shodan.io/search?query={urllib.parse.quote(host)}"


# ---- #95 system tray icon (pystray if available) ----
def has_pystray() -> bool:
    try:
        import pystray, PIL  # noqa: F401
        return True
    except ImportError:
        return False


def show_tray_icon(on_click_callback) -> None:
    """No-op if pystray not installed. Otherwise spawns a tray icon in the
    background that fires `on_click_callback` when clicked."""
    if not has_pystray():
        return
    import threading
    def _run():
        from pystray import Icon, MenuItem, Menu
        from PIL import Image, ImageDraw
        img = Image.new("RGB", (64, 64), "navy")
        d = ImageDraw.Draw(img)
        d.rectangle((10, 10, 54, 54), fill="white")
        d.text((20, 20), "WS", fill="navy")
        icon = Icon("wpsecscan", img, "WPSecScan",
                     menu=Menu(MenuItem("Open", on_click_callback),
                               MenuItem("Quit", lambda i, _: i.stop())))
        icon.run()
    threading.Thread(target=_run, daemon=True).start()


# ---- #96 desktop notification ----
def desktop_notify(title: str, msg: str) -> None:
    """Best-effort cross-platform desktop notification. Title/msg are
    escaped for the platform's markup so they can't inject commands.
    No-op on any failure."""
    def _xml_escape(s: str) -> str:
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                      .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))
    def _apple_escape(s: str) -> str:
        # AppleScript string escapes: \ and "
        return str(s).replace("\\", "\\\\").replace('"', '\\"')

    sysname = platform.system()
    try:
        if sysname == "Windows":
            import subprocess
            t = _xml_escape(title)
            m = _xml_escape(msg)
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]>$null; "
                f"$xml = '<toast><visual><binding template=\"ToastText02\"><text id=\"1\">{t}</text><text id=\"2\">{m}</text></binding></visual></toast>'; "
                "$doc = New-Object Windows.Data.Xml.Dom.XmlDocument; $doc.LoadXml($xml); "
                "$t = New-Object Windows.UI.Notifications.ToastNotification $doc; "
                "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('WPSecScan').Show($t)"
            )
            subprocess.Popen(["powershell", "-NoProfile", "-Command", ps],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sysname == "Darwin":
            import subprocess
            t = _apple_escape(title)
            m = _apple_escape(msg)
            subprocess.Popen(["osascript", "-e",
                              f'display notification "{m}" with title "{t}"'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sysname == "Linux":
            # notify-send takes args via argv — no shell interpolation risk
            import subprocess
            subprocess.Popen(["notify-send", title, msg],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        pass


# ---- #97 battery / activity pause ----
def on_battery() -> bool:
    """True if running on battery power."""
    try:
        import psutil  # optional
        b = psutil.sensors_battery()
        return b is not None and not b.power_plugged
    except (ImportError, Exception):  # noqa: BLE001
        return False


# ---- #98 color themes ----
THEMES = {
    "dark":       {"bg": "#0d1117", "fg": "#e6edf3", "accent": "#2f81f7"},
    "light":      {"bg": "#ffffff", "fg": "#0d1117", "accent": "#0969da"},
    "matrix":     {"bg": "#000000", "fg": "#00ff00", "accent": "#33ff33"},
    "hacker":     {"bg": "#1a0000", "fg": "#ff5252", "accent": "#ff9090"},
    "corporate":  {"bg": "#f4f6f8", "fg": "#222222", "accent": "#1565c0"},
    "high-contrast": {"bg": "#000000", "fg": "#ffff00", "accent": "#ffffff"},
}


# ---- #99 sound effects ----
def play_sound(name: str) -> None:
    """name ∈ 'finding', 'complete', 'error'. No-op on failure."""
    try:
        if platform.system() == "Windows":
            import winsound
            freq = {"finding": 880, "complete": 660, "error": 220}.get(name, 440)
            winsound.Beep(freq, 100)
    except Exception:  # noqa: BLE001
        pass


# ---- #100 onboarding video URL ----
ONBOARDING_VIDEO_URL = "https://github.com/bryanflowers/wpsecscan#readme"  # placeholder


# ---- #101 achievements ----
def _achievements_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "achievements.json"


ACHIEVEMENTS = {
    "first_scan":        {"name": "First scan", "desc": "Ran your first WPSecScan."},
    "ten_scans":         {"name": "Regular", "desc": "Ran 10 scans."},
    "hundred_scans":     {"name": "Power user", "desc": "Ran 100 scans."},
    "first_critical":    {"name": "First critical", "desc": "Found your first critical."},
    "clean_streak_30":   {"name": "Clean streak", "desc": "30 days with zero criticals."},
    "demo_complete":     {"name": "Tour guide", "desc": "Ran the demo."},
    "custom_template":   {"name": "Tinkerer", "desc": "Authored a YAML template."},
    "all_reporters":     {"name": "Completionist", "desc": "Generated every reporter format in one scan."},
}


def unlock(achievement_id: str) -> bool:
    """Mark an achievement unlocked. Returns True if newly unlocked."""
    p = _achievements_path()
    try:
        d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        d = {}
    if achievement_id in d:
        return False
    if achievement_id not in ACHIEVEMENTS:
        return False
    import time
    d[achievement_id] = {"unlocked_at": time.time()}
    try:
        p.write_text(json.dumps(d, indent=2), encoding="utf-8")
    except OSError:
        pass
    return True


def unlocked_achievements() -> list[dict]:
    p = _achievements_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for aid, meta in ACHIEVEMENTS.items():
        if aid in d:
            out.append({"id": aid, **meta, "unlocked_at": d[aid].get("unlocked_at")})
    return out


# ---- #102 custom CSS loader for HTML reports ----
def custom_report_css() -> str:
    """Return contents of ~/.wpsecscan/report.css or empty string."""
    from . import history as _h
    p = Path(_h._home()) / "report.css"
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


# ---- #89 drag-drop helper ----
def parse_dropped_targets(file_path: str) -> list[str]:
    """Read URLs from a dropped text file (one per line, # comments)."""
    out: list[str] = []
    try:
        for line in Path(file_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    except OSError:
        pass
    return out


# ---- #94 in-app changelog viewer ----
def latest_changelog_section() -> str:
    """Return the [Unreleased] / latest version's CHANGELOG.md section for
    display in an 'in-app what's new' popup."""
    p = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    if not p.exists():
        return "(CHANGELOG.md not found)"
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return "(CHANGELOG.md unreadable)"
    # Find the first '## [' header and grab through the next '## [' or end
    import re
    m = re.search(r"^(## \[.*?\][^\n]*\n.*?)(?=\n## \[|\Z)", text, re.MULTILINE | re.DOTALL)
    return m.group(1) if m else text[:3000]
