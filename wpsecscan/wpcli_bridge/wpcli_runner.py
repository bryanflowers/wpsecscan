"""When wp-cli is available locally, use it for authoritative data.

Round-64 #173 — many WP-internal facts (real plugin versions, mu-
plugins, scheduled crons, salt freshness) are far easier to query
locally via wp-cli than to infer from HTTP. This bridge tries wp-cli
first; checks fall back to HTTP fingerprinting if wp-cli isn't
installed or the path isn't accessible.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def wpcli_available() -> bool:
    return shutil.which("wp") is not None


def run(wp_path: str, *args: str, timeout: int = 30) -> dict:
    """Run `wp --path=<wp_path> <args>` and return {stdout, stderr, returncode}.

    Always uses list args (no shell) to avoid injection.
    """
    if not wpcli_available():
        return {"stdout": "", "stderr": "wp-cli not installed", "returncode": -1}
    if not Path(wp_path).is_dir():
        return {"stdout": "", "stderr": f"path not found: {wp_path}", "returncode": -1}
    cmd = ["wp", f"--path={wp_path}", *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "returncode": -1}


def list_plugins(wp_path: str) -> list[dict]:
    r = run(wp_path, "plugin", "list", "--format=json")
    if r["returncode"] != 0:
        return []
    try:
        return json.loads(r["stdout"])
    except ValueError:
        return []


def list_users(wp_path: str) -> list[dict]:
    r = run(wp_path, "user", "list", "--format=json")
    if r["returncode"] != 0:
        return []
    try:
        return json.loads(r["stdout"])
    except ValueError:
        return []


def list_cron_events(wp_path: str) -> list[dict]:
    r = run(wp_path, "cron", "event", "list", "--format=json")
    if r["returncode"] != 0:
        return []
    try:
        return json.loads(r["stdout"])
    except ValueError:
        return []


def wp_version(wp_path: str) -> str | None:
    r = run(wp_path, "core", "version")
    if r["returncode"] != 0:
        return None
    return r["stdout"].strip() or None


def db_check(wp_path: str) -> dict:
    """Returns wp db check output (table corruption etc.)."""
    return run(wp_path, "db", "check")


def list_transients(wp_path: str) -> list[str]:
    """Returns the names of stored transients (useful for spotting webshell-style state)."""
    r = run(wp_path, "transient", "list", "--format=csv")
    if r["returncode"] != 0:
        return []
    out = []
    for i, line in enumerate(r["stdout"].splitlines()):
        if i == 0:
            continue  # header
        out.append(line.split(",", 1)[0])
    return out
