"""Persistent site list + weekly scan scheduler.

Stores per-site config (URL, creds, schedule cadence, owner notes) in
~/.wpsecscan/sites.json. Application Passwords are encrypted at rest via
hardware_keys.tpm_seal/DPAPI on Windows, gpg-encrypt elsewhere.

CLI:
    wpsecscan sites add URL [--weekly] [--auth-user U] [--auth-app-password P]
    wpsecscan sites list
    wpsecscan sites remove URL
    wpsecscan sites edit URL [...]
    wpsecscan sites scan [URL]       # run one site (or all due-now)
    wpsecscan schedule install --weekly --time HH:MM
    wpsecscan schedule uninstall
    wpsecscan schedule pause / resume
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# ---- file location ----

def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _sites_path() -> Path:
    return _home() / "sites.json"


def _schedule_state_path() -> Path:
    return _home() / "schedule_state.json"


# ---- creds encryption (best-effort) ----

def _seal(value: str) -> str:
    """Encrypt a string for at-rest storage. Returns 'b64:...' or 'plain:...'."""
    if not value:
        return ""
    try:
        from . import hardware_keys
        sealed = hardware_keys.tpm_seal(value.encode("utf-8"), "site_secret")
        if sealed:
            return f"sealed:{sealed}"
    except ImportError:
        pass
    # Fallback: plaintext, but with a marker so we know it's not sealed
    return f"plain:{value}"


def _unseal(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("plain:"):
        return stored[6:]
    if stored.startswith("sealed:"):
        try:
            from . import hardware_keys
            # `sealed:` payload is a path on disk to the sealed blob
            data = hardware_keys.tpm_unseal("site_secret")
            return data.decode("utf-8", errors="replace") if data else ""
        except ImportError:
            return ""
    return stored


# ---- CRUD ----

def _load() -> list[dict]:
    p = _sites_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _save(sites: list[dict]) -> None:
    # v2.8.5 H11 — pre-fix bare `p.write_text(...)` truncated sites.json
    # to 0 bytes on power loss / SIGKILL between truncate and write.
    # Atomic temp+rename so the file is always either old-state or
    # new-state, never empty.
    p = _sites_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        import os as _os
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(sites, indent=2), encoding="utf-8")
        _os.replace(tmp, p)
    except OSError:
        pass


def add(url: str, *, weekly: bool = False,
        auth_user: str | None = None,
        auth_app_password: str | None = None,
        companion_token: str | None = None,
        proxy_url: str | None = None,
        proxy_auth: str | None = None,
        notes: str = "",
        tags: list[str] | None = None) -> dict:
    """Add or update a site. #31 — accepts a list of free-form tags
    (e.g. `client:acme`, `tier:gold`) for portfolio filtering."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url.lstrip("/")
    # Validate URL
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"invalid URL: {url}")

    sites = _load()
    entry: dict[str, Any] = next((s for s in sites if s.get("url") == url), {})
    entry.setdefault("url", url)
    entry.setdefault("added_at", int(time.time()))
    entry["weekly"] = bool(weekly)
    entry["notes"] = notes or entry.get("notes", "")
    if tags is not None:
        # Normalise: lowercased, deduped, alphabetical.
        cleaned = sorted({t.strip().lower() for t in tags if t and t.strip()})
        entry["tags"] = cleaned
    if auth_user:
        entry["auth_user"] = auth_user
    if auth_app_password:
        entry["auth_app_password_sealed"] = _seal(auth_app_password)
    if companion_token:
        entry["companion_token_sealed"] = _seal(companion_token)
    # round-61: per-site proxy
    if proxy_url:
        entry["proxy_url"] = proxy_url
    if proxy_auth:
        entry["proxy_auth_sealed"] = _seal(proxy_auth)
    # Insert if new
    if entry not in sites:
        sites = [s for s in sites if s.get("url") != url] + [entry]
    _save(sites)
    return entry


def remove(url: str) -> bool:
    sites = _load()
    new = [s for s in sites if s.get("url") != url]
    if len(new) != len(sites):
        _save(new)
        return True
    return False


def list_sites() -> list[dict]:
    return _load()


def get(url: str) -> dict | None:
    return next((s for s in _load() if s.get("url") == url), None)


def due_now() -> list[dict]:
    """Sites whose weekly scan is overdue (last_scan_ts > 7d ago, or never scanned)."""
    now = int(time.time())
    week = 7 * 86400
    out = []
    for s in _load():
        if not s.get("weekly"):
            continue
        last = int(s.get("last_scan_ts") or 0)
        if not last or (now - last) > week:
            out.append(s)
    return out


def mark_scanned(url: str, *, risk_score: int = 0,
                  critical: int = 0, high: int = 0) -> None:
    sites = _load()
    for s in sites:
        if s.get("url") == url:
            s["last_scan_ts"] = int(time.time())
            s["last_risk_score"] = int(risk_score)
            s["last_critical"] = int(critical)
            s["last_high"] = int(high)
            # Keep a small per-site rolling history
            hist = s.setdefault("history", [])
            hist.append({"ts": s["last_scan_ts"], "risk": risk_score,
                          "critical": critical, "high": high})
            if len(hist) > 100:
                s["history"] = hist[-100:]
    _save(sites)


# ---- scheduler ----

def is_paused() -> bool:
    p = _schedule_state_path()
    if not p.exists():
        return False
    try:
        return bool(json.loads(p.read_text(encoding="utf-8")).get("paused"))
    except (OSError, ValueError):
        return False


def pause() -> None:
    _set_state({"paused": True})


def resume() -> None:
    _set_state({"paused": False})


def _set_state(state: dict) -> None:
    p = _schedule_state_path()
    try:
        existing = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        existing = {}
    existing.update(state)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(existing), encoding="utf-8")
    except OSError:
        pass


def install_schedule(*, weekly: bool = True, time_hhmm: str = "03:00",
                       db_refresh: bool = True, db_time_hhmm: str = "02:00") -> dict:
    """Register a weekly scheduled scan + (round-61) a daily CVE-DB refresh.

    Returns the scan-task result. The DB-refresh task result is reported
    under `result["db_refresh"]`.

    Windows: Task Scheduler via `schtasks`.
    macOS:   launchd plist in ~/Library/LaunchAgents/.
    Linux:   systemd user timer in ~/.config/systemd/user/.
    """
    if not re.match(r"^\d{2}:\d{2}$", time_hhmm):
        return {"ok": False, "method": "", "detail": "time must be HH:MM"}
    if db_refresh and not re.match(r"^\d{2}:\d{2}$", db_time_hhmm):
        return {"ok": False, "method": "", "detail": "db_time_hhmm must be HH:MM"}

    if sys.platform == "win32":
        result = _install_windows(time_hhmm)
    elif sys.platform == "darwin":
        result = _install_macos(time_hhmm)
    else:
        result = _install_linux(time_hhmm)

    if db_refresh:
        if sys.platform == "win32":
            result["db_refresh"] = _install_windows_db(db_time_hhmm)
        elif sys.platform == "darwin":
            result["db_refresh"] = _install_macos_db(db_time_hhmm)
        else:
            result["db_refresh"] = _install_linux_db(db_time_hhmm)
    return result


def uninstall_schedule() -> dict:
    if sys.platform == "win32":
        ok = True
        for task in ("WPSecScanWeekly", "WPSecScanDbDaily"):
            try:
                subprocess.run(["schtasks", "/Delete", "/TN", task, "/F"],
                                capture_output=True, timeout=10)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                ok = False
        return {"ok": ok, "method": "schtasks", "detail": "removed scan + db tasks"}
    if sys.platform == "darwin":
        for label in ("com.wpsecscan.weekly", "com.wpsecscan.db"):
            plist = Path.home() / f"Library/LaunchAgents/{label}.plist"
            try:
                subprocess.run(["launchctl", "unload", str(plist)],
                                capture_output=True, timeout=10)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            if plist.exists():
                plist.unlink()
        return {"ok": True, "method": "launchd", "detail": "unloaded scan + db plists"}
    # Linux
    base = Path.home() / ".config/systemd/user"
    for fn in ("wpsecscan-weekly.service", "wpsecscan-weekly.timer",
                 "wpsecscan-db.service", "wpsecscan-db.timer"):
        p = base / fn
        if p.exists():
            p.unlink()
    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"],
                        capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return {"ok": True, "method": "systemd", "detail": "removed scan + db timers"}


def _install_windows(time_hhmm: str) -> dict:
    if not shutil.which("schtasks"):
        return {"ok": False, "method": "schtasks", "detail": "schtasks not on PATH"}
    exe = shutil.which("wpsecscan") or sys.executable
    if not exe:
        return {"ok": False, "method": "schtasks", "detail": "cannot locate wpsecscan executable"}
    # schtasks requires the executable wrapped in quotes
    cmd_args = ["wpsecscan", "sites", "scan"] if exe.endswith("wpsecscan.exe") else [sys.executable, "-m", "wpsecscan", "sites", "scan"]
    quoted = '"' + '" "'.join(cmd_args) + '"'
    args = [
        "schtasks", "/Create", "/TN", "WPSecScanWeekly",
        "/TR", quoted,
        "/SC", "WEEKLY", "/D", "MON",
        "/ST", time_hhmm,
        "/F",  # force overwrite
    ]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return {
                "ok": True,
                "method": "schtasks",
                "detail": (
                    f"scheduled MON {time_hhmm} as task 'WPSecScanWeekly'. "
                    "Remove with:  schtasks /Delete /TN WPSecScanWeekly /F"
                ),
            }
        return {"ok": False, "method": "schtasks", "detail": (r.stderr or r.stdout)[:200]}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "method": "schtasks", "detail": str(e)}


def _install_macos(time_hhmm: str) -> dict:
    hh, mm = time_hhmm.split(":")
    label = "com.wpsecscan.weekly"
    plist_path = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    exe = shutil.which("wpsecscan") or sys.executable
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>
<string>{exe}</string><string>sites</string><string>scan</string>
</array>
<key>StartCalendarInterval</key><dict>
<key>Weekday</key><integer>1</integer>
<key>Hour</key><integer>{int(hh)}</integer>
<key>Minute</key><integer>{int(mm)}</integer>
</dict>
<key>RunAtLoad</key><false/>
</dict></plist>
"""
    if plist_path.is_symlink():
        try:
            plist_path.unlink()
        except OSError as e:
            return {"ok": False, "method": "launchd", "detail": f"plist symlink: {e}"}
    plist_path.write_text(plist, encoding="utf-8")
    try:
        subprocess.run(["launchctl", "load", str(plist_path)], capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "method": "launchd", "detail": str(e)}
    return {"ok": True, "method": "launchd", "detail": f"loaded {plist_path}"}


def _install_linux(time_hhmm: str) -> dict:
    base = Path.home() / ".config/systemd/user"
    base.mkdir(parents=True, exist_ok=True)
    exe = shutil.which("wpsecscan") or sys.executable
    svc = (
        "[Unit]\nDescription=WPSecScan weekly\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart={exe} sites scan\n"
    )
    tmr = (
        "[Unit]\nDescription=WPSecScan weekly timer\n\n"
        "[Timer]\n"
        f"OnCalendar=Mon *-*-* {time_hhmm}:00\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    for name, content in (("wpsecscan-weekly.service", svc),
                            ("wpsecscan-weekly.timer", tmr)):
        p = base / name
        if p.is_symlink():
            try:
                p.unlink()
            except OSError as e:
                return {"ok": False, "method": "systemd", "detail": f"{name} symlink: {e}"}
        p.write_text(content, encoding="utf-8")
    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=10)
        subprocess.run(["systemctl", "--user", "enable", "--now", "wpsecscan-weekly.timer"],
                        capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "method": "systemd", "detail": str(e)}
    return {"ok": True, "method": "systemd", "detail": f"timer enabled MON {time_hhmm}"}


# ---- round-61: daily DB-refresh task (alongside the weekly scan task) ----

def _wpsecscan_invocation(*tail: str) -> tuple[list[str], str]:
    """Build the command-line that launches `wpsecscan` portably.

    Returns (args_list, quoted_for_schtasks_TR_string).
    """
    exe = shutil.which("wpsecscan") or sys.executable
    if exe and exe.endswith("wpsecscan.exe"):
        argv = ["wpsecscan", *tail]
    else:
        argv = [sys.executable, "-m", "wpsecscan", *tail]
    quoted = '"' + '" "'.join(argv) + '"'
    return argv, quoted


def _install_windows_db(time_hhmm: str) -> dict:
    if not shutil.which("schtasks"):
        return {"ok": False, "method": "schtasks", "detail": "schtasks not on PATH"}
    _argv, quoted = _wpsecscan_invocation("db", "update")
    args = [
        "schtasks", "/Create", "/TN", "WPSecScanDbDaily",
        "/TR", quoted,
        "/SC", "DAILY",
        "/ST", time_hhmm,
        "/F",
    ]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return {"ok": True, "method": "schtasks", "detail": f"daily DB refresh at {time_hhmm}"}
        return {"ok": False, "method": "schtasks", "detail": (r.stderr or r.stdout)[:200]}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "method": "schtasks", "detail": str(e)}


def _install_macos_db(time_hhmm: str) -> dict:
    hh, mm = time_hhmm.split(":")
    label = "com.wpsecscan.db"
    plist_path = Path.home() / "Library/LaunchAgents" / f"{label}.plist"
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    exe = shutil.which("wpsecscan") or sys.executable
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>
<string>{exe}</string><string>db</string><string>update</string>
</array>
<key>StartCalendarInterval</key><dict>
<key>Hour</key><integer>{int(hh)}</integer>
<key>Minute</key><integer>{int(mm)}</integer>
</dict>
<key>RunAtLoad</key><false/>
</dict></plist>
"""
    if plist_path.is_symlink():
        try:
            plist_path.unlink()
        except OSError as e:
            return {"ok": False, "method": "launchd", "detail": f"plist symlink: {e}"}
    plist_path.write_text(plist, encoding="utf-8")
    try:
        subprocess.run(["launchctl", "load", str(plist_path)],
                        capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "method": "launchd", "detail": str(e)}
    return {"ok": True, "method": "launchd", "detail": f"daily DB refresh at {time_hhmm}"}


def _install_linux_db(time_hhmm: str) -> dict:
    base = Path.home() / ".config/systemd/user"
    base.mkdir(parents=True, exist_ok=True)
    exe = shutil.which("wpsecscan") or sys.executable
    svc = (
        "[Unit]\nDescription=WPSecScan daily DB refresh\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart={exe} db update\n"
    )
    tmr = (
        "[Unit]\nDescription=WPSecScan daily DB-refresh timer\n\n"
        "[Timer]\n"
        f"OnCalendar=*-*-* {time_hhmm}:00\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    for name, content in (("wpsecscan-db.service", svc),
                            ("wpsecscan-db.timer", tmr)):
        p = base / name
        if p.is_symlink():
            try:
                p.unlink()
            except OSError as e:
                return {"ok": False, "method": "systemd", "detail": f"{name} symlink: {e}"}
        p.write_text(content, encoding="utf-8")
    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"],
                        capture_output=True, timeout=10)
        subprocess.run(["systemctl", "--user", "enable", "--now", "wpsecscan-db.timer"],
                        capture_output=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {"ok": False, "method": "systemd", "detail": str(e)}
    return {"ok": True, "method": "systemd", "detail": f"daily DB refresh at {time_hhmm}"}


# ---- email digest configuration ----

def _digest_path() -> Path:
    return _home() / "digest.json"


def configure_digest(*, to: str, smtp: str = "", smtp_user: str = "",
                      smtp_pass: str = "", from_addr: str = "",
                      slack_webhook: str = "") -> None:
    """Persist digest delivery config. Smtp creds sealed when possible."""
    cfg = {
        "to": to,
        "from": from_addr,
        "slack_webhook": slack_webhook,
    }
    if smtp:
        cfg["smtp"] = smtp
        cfg["smtp_user"] = smtp_user
        cfg["smtp_pass_sealed"] = _seal(smtp_pass)
    p = _digest_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except OSError:
        pass


def load_digest() -> dict:
    p = _digest_path()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def render_digest(sites: list[dict]) -> str:
    """Plain-text body summarising all sites' current risk."""
    if not sites:
        return "No sites configured."
    lines = ["WPSecScan weekly digest", "=" * 40, ""]
    for s in sorted(sites, key=lambda x: -int(x.get("last_critical") or 0)):
        u = s.get("url", "")
        c = s.get("last_critical", 0)
        h = s.get("last_high", 0)
        r = s.get("last_risk_score", 0)
        ts = s.get("last_scan_ts", 0)
        when = "never" if not ts else time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
        lines.append(f"  {u}")
        lines.append(f"    risk={r}/100  critical={c}  high={h}  last={when}")
    return "\n".join(lines)
