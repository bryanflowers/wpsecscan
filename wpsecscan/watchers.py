"""Round-60 #26-30 — daemon-friendly watchers.

#26 wp_version_drift_alert  — notice when wp.org publishes a new core version
#28 malware_scan_diff       — compare WP core file hashes against wp.org official hashes
#29 dns_change_watcher      — notice NS / A / MX changes on tracked sites
#30 subdomain_takeover_scan — daily check for dangling-CNAME takeover candidates

Each function writes its state under ~/.wpsecscan/watchers/<name>.json so
they can run from cron / Task Scheduler and only fire alerts on change.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _state_path(name: str) -> Path:
    p = _home() / "watchers"
    p.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "default"
    return p / f"{safe}.json"


def _load_state(name: str) -> dict:
    p = _state_path(name)
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(name: str, state: dict) -> None:
    p = _state_path(name)
    try:
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def _http_get(url: str, timeout: float = 8.0) -> str:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return ""
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/watchers"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError):
        return ""


def _notify(title: str, message: str) -> None:
    try:
        from . import notify
        notify.notify(title, message)
    except Exception:  # noqa: BLE001
        pass


# ---- #26 WordPress core version drift ----

def wp_version_drift_alert() -> dict:
    """Hit api.wordpress.org/core/version-check; alert on a new release.
    Returns {previous, latest, changed: bool}."""
    raw = _http_get("https://api.wordpress.org/core/version-check/1.7/")
    if not raw:
        return {"changed": False, "error": "no response"}
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return {"changed": False, "error": "bad json"}
    latest = (d.get("offers") or [{}])[0].get("version", "")
    state = _load_state("wp_version_drift")
    prev = state.get("latest", "")
    changed = bool(latest and latest != prev)
    state.update({"latest": latest, "last_check": int(time.time()),
                    "previous": prev if changed else state.get("previous", "")})
    _save_state("wp_version_drift", state)
    if changed:
        _notify(f"WordPress {latest} released", f"Was {prev}, now {latest}. Update your sites.")
    return {"changed": changed, "latest": latest, "previous": prev}


# ---- #28 malware-scan diff via wp.org official hashes ----

def fetch_core_hashes(version: str) -> dict | None:
    """Pull /core/checksums/1.0/?version=X. Returns {path: md5}."""
    raw = _http_get(f"https://api.wordpress.org/core/checksums/1.0/?version={version}&locale=en_US")
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return d.get("checksums", {}) if isinstance(d, dict) else None
    except json.JSONDecodeError:
        return None


def malware_scan_diff(site_root: str, version: str) -> dict:
    """Compare core file md5s against wp.org official. site_root is the
    file-system path to the WP install. Returns {modified: [...], extra: [...], missing: [...]}."""
    official = fetch_core_hashes(version)
    if not official:
        return {"error": "could not fetch official hashes"}
    root = Path(site_root)
    if not root.is_dir():
        return {"error": f"not a directory: {site_root}"}
    modified = []
    missing = []
    for rel, want_md5 in official.items():
        full = root / rel
        if not full.is_file():
            missing.append(rel)
            continue
        try:
            got = hashlib.md5(full.read_bytes()).hexdigest()
        except OSError:
            continue
        if got != want_md5:
            modified.append(rel)
    return {"modified": modified, "missing": missing,
             "checked": len(official), "diff_count": len(modified) + len(missing)}


# ---- #29 DNS change watcher ----

def _dig(record_type: str, name: str) -> str:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return ""
    try:
        r = subprocess.run(["dig", "+short", record_type, name],
                            capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            return (r.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    try:
        r = subprocess.run(["nslookup", "-type=" + record_type, name],
                            capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            return (r.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ""


def dns_change_watcher(host: str) -> dict:
    """Snapshot NS / A / MX; alert on change. Returns {changed_records: [...]}."""
    if not host or not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        return {"error": "invalid host"}
    name = f"dns:{host}"
    state = _load_state(name)
    cur = {rt: _dig(rt, host) for rt in ("NS", "A", "AAAA", "MX")}
    changed: list[str] = []
    for rt, val in cur.items():
        prev = state.get(rt, "")
        if prev and val and val != prev:
            changed.append(rt)
    if changed:
        _notify(f"DNS change on {host}",
                 "Changed records: " + ", ".join(changed))
    state.update({**cur, "last_check": int(time.time())})
    _save_state(name, state)
    return {"changed_records": changed, "current": cur}


# ---- #30 subdomain takeover monitor ----

TAKEOVER_FINGERPRINTS = [
    ("There is no app configured at that hostname",       "Heroku"),
    ("NoSuchBucket",                                      "AWS S3"),
    ("The specified bucket does not exist",               "AWS S3"),
    ("project not found",                                 "Vercel"),
    ("Whoops, that page is gone.",                        "Tumblr"),
    ("Heroku | No such app",                              "Heroku"),
    ("Sorry, this shop is currently unavailable.",        "Shopify"),
    ("The page you were looking for doesn't exist.",      "Help Scout"),
    ("Page Not Found",                                    "Webflow"),
    ("not been linked to a Statuspage",                   "Statuspage"),
]


def subdomain_takeover_scan(subdomains: list[str]) -> list[dict]:
    """For each subdomain, GET it and check the body for known-takeover fingerprints.
    Returns list of {subdomain, vendor, body_snippet}."""
    out = []
    name = "takeover"
    state = _load_state(name)
    seen = set(state.get("known_takeovers", []))
    for sub in (subdomains or [])[:200]:
        if not re.match(r"^[a-zA-Z0-9.\-]+$", sub):
            continue
        body = ""
        for proto in ("https://", "http://"):
            body = _http_get(proto + sub, timeout=6.0)
            if body:
                break
        if not body:
            continue
        snippet = body[:500]
        for fp, vendor in TAKEOVER_FINGERPRINTS:
            if fp in snippet:
                row = {"subdomain": sub, "vendor": vendor,
                        "body_snippet": snippet[:200]}
                if sub not in seen:
                    _notify(f"Possible subdomain takeover: {sub}",
                              f"Vendor: {vendor}. Body: {snippet[:200]}")
                    seen.add(sub)
                out.append(row)
                break
    state["known_takeovers"] = sorted(seen)[-500:]
    state["last_check"] = int(time.time())
    _save_state(name, state)
    return out
