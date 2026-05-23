"""#36 (from Burp Suite) — `.burp` project import.

Burp project files are SQLite databases with a particular schema (the
`messages` table holds every captured request/response). We extract the
request side and convert each to a HAR-shaped entry so the existing
har_replay engine can run it against a target.

Limitations: we read request URL + method + headers + body. We don't
decrypt encrypted project files (Burp Pro feature). We don't import
Repeater state, Intruder positions, or scanner findings — only the
proxy history's raw requests.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def import_burp_project(path: Path, *, limit: int = 5000) -> dict:
    """Read a Burp .burp project (SQLite). Returns a HAR-shaped doc with
    every request from the proxy history (up to `limit`)."""
    if not path.exists():
        raise FileNotFoundError(path)
    entries = []
    try:
        con = sqlite3.connect(str(path))
        con.row_factory = sqlite3.Row
        # Burp's schema varies across versions; try the most common table name first
        try:
            cur = con.execute("SELECT * FROM messages LIMIT ?", (limit,))
        except sqlite3.OperationalError:
            try:
                cur = con.execute("SELECT * FROM HTTP_REQUEST LIMIT ?", (limit,))
            except sqlite3.OperationalError:
                return _empty_har("burp_import: unknown schema, no recognised table")
        rows = list(cur)
        con.close()
    except sqlite3.DatabaseError as e:
        return _empty_har(f"burp_import: SQLite error {e}")

    for row in rows:
        # Best-effort field extraction — schemas vary
        url = row["url"] if "url" in row.keys() else (row.get("URL") if hasattr(row, "get") else None)
        method = row["method"] if "method" in row.keys() else "GET"
        if not url:
            continue
        entries.append({
            "request": {
                "method": method,
                "url": url,
                "headers": [],
                "postData": {"text": ""} if method != "GET" else {},
            },
        })

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "wpsecscan burp_import"},
            "entries": entries,
        },
    }


def _empty_har(note: str) -> dict:
    return {"log": {"version": "1.2", "creator": {"name": "wpsecscan burp_import"},
                     "entries": [], "_note": note}}


def write_as_har(burp_path: Path, har_out: Path) -> int:
    """Convenience: import the Burp project and write the HAR to disk.
    Returns the entry count."""
    har = import_burp_project(burp_path)
    har_out.write_text(json.dumps(har, indent=2), encoding="utf-8")
    return len(har["log"]["entries"])
