"""Offline password-audit helper.

Reads a CSV/SQL dump of wp_users that the user has exported from their own
database, formats the hashes for hashcat, and prints copy-paste instructions
for running the crack locally.

NO network calls. Strictly local file I/O. Doesn't invoke hashcat — the user
runs it themselves on their own machine.

Usage:
  wpsecscan --password-audit path/to/wp_users.csv
"""
from __future__ import annotations

import csv
import re
from pathlib import Path

# (prefix, hashcat mode, friendly name)
HASH_FORMATS: tuple[tuple[str, int, str], ...] = (
    ("$P$", 400,  "phpass (WordPress default)"),
    ("$H$", 400,  "phpass variant"),
    ("$wp$", 400, "WordPress new-style"),
    ("$2y$", 3200, "bcrypt (some WP hardening plugins)"),
    ("$2a$", 3200, "bcrypt"),
    ("$2b$", 3200, "bcrypt"),
    ("$argon2", 13900, "argon2"),  # not commonly seen in WP
)


def _detect_format(hash_value: str) -> tuple[int, str] | None:
    for prefix, mode, name in HASH_FORMATS:
        if hash_value.startswith(prefix):
            return mode, name
    return None


def _read_csv_or_sql(path: Path) -> list[tuple[str, str]]:
    """Returns [(user_login, user_pass_hash), ...].
    Accepts CSV (with header user_login, user_pass) or SQL INSERT lines."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if text.lstrip().startswith("INSERT INTO") or "INSERT INTO `wp_users`" in text or "INSERT INTO wp_users" in text:
        return _parse_sql_inserts(text)
    # CSV
    out: list[tuple[str, str]] = []
    reader = csv.DictReader(text.splitlines())
    fieldnames = [(f or "").strip().lower() for f in (reader.fieldnames or [])]
    if not fieldnames:
        return out
    # Tolerant column lookup
    login_keys = ("user_login", "login", "username", "user")
    pass_keys = ("user_pass", "pass", "password", "hash")
    login_key = next((k for k in fieldnames if k in login_keys), None)
    pass_key = next((k for k in fieldnames if k in pass_keys), None)
    if not login_key or not pass_key:
        raise ValueError(
            f"CSV header doesn't include both a login column and a password column. "
            f"Found headers: {fieldnames}. Expected one of {login_keys} and one of {pass_keys}."
        )
    for row in reader:
        login = (row.get(login_key) or "").strip()
        pwd = (row.get(pass_key) or "").strip()
        if login and pwd:
            out.append((login, pwd))
    return out


_SQL_VALUES_RE = re.compile(
    r"INSERT INTO\s+`?wp_users`?\s*\([^)]*\)\s+VALUES\s+(.+?);",
    re.IGNORECASE | re.DOTALL,
)


def _split_sql_tuples(blob: str) -> list[str]:
    """Given the VALUES portion '(a,b,c),(d,e,f)', return ['a,b,c', 'd,e,f'].
    State machine: tracks paren depth and quote state."""
    tuples: list[str] = []
    cur = ""
    depth = 0
    in_quote = False
    i = 0
    while i < len(blob):
        ch = blob[i]
        if in_quote:
            if ch == "\\" and i + 1 < len(blob):
                cur += blob[i:i + 2]
                i += 2
                continue
            if ch == "'":
                in_quote = False
            cur += ch
        else:
            if ch == "'":
                in_quote = True
                cur += ch
            elif ch == "(":
                if depth == 0:
                    cur = ""
                else:
                    cur += ch
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    tuples.append(cur)
                    cur = ""
                else:
                    cur += ch
            else:
                if depth >= 1:
                    cur += ch
        i += 1
    return tuples


def _split_csv_row(row: str) -> list[str]:
    """Split 'a,b,c,'d e','f'' into [a,b,c,d e,f] respecting single-quoted strings."""
    vals: list[str] = []
    cur = ""
    in_quote = False
    i = 0
    while i < len(row):
        ch = row[i]
        if in_quote:
            if ch == "\\" and i + 1 < len(row):
                cur += row[i + 1]
                i += 2
                continue
            if ch == "'":
                in_quote = False
            else:
                cur += ch
        else:
            if ch == "'":
                in_quote = True
            elif ch == ",":
                vals.append(cur.strip())
                cur = ""
            else:
                cur += ch
        i += 1
    if cur or row.endswith(","):
        vals.append(cur.strip())
    return vals


def _parse_sql_inserts(text: str) -> list[tuple[str, str]]:
    """Naive SQL parser — looks for INSERT INTO wp_users (...) VALUES (...),(...);
    Standard wp_users column order: (ID, user_login, user_pass, ...)."""
    out: list[tuple[str, str]] = []
    for m in _SQL_VALUES_RE.finditer(text):
        for row in _split_sql_tuples(m.group(1)):
            vals = _split_csv_row(row)
            if len(vals) >= 3:
                out.append((vals[1], vals[2]))
    return out


def audit(input_path: Path) -> dict:
    """Returns a dict with: hash_count, output_path, format_summary, instructions."""
    rows = _read_csv_or_sql(input_path)
    if not rows:
        raise ValueError("No (user, hash) pairs parsed from the input file")

    mode_counts: dict[int, int] = {}
    output_lines: list[str] = []
    unknown_hashes = 0
    for login, pwd in rows:
        fmt = _detect_format(pwd)
        if not fmt:
            unknown_hashes += 1
            continue
        mode, _name = fmt
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        output_lines.append(f"{login}:{pwd}")

    if not output_lines:
        raise ValueError(
            f"None of the {len(rows)} rows looked like recognizable password hashes. "
            "Make sure the password column contains hashes (starting with $P$, $H$, $wp$, $2y$, etc.) — not plaintext."
        )

    out_path = input_path.with_suffix(input_path.suffix + ".hashcat.txt")
    out_path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")

    primary_mode = max(mode_counts.items(), key=lambda kv: kv[1])[0]
    primary_name = next((n for p, m, n in HASH_FORMATS if m == primary_mode), str(primary_mode))

    instructions = (
        f"Hashes written to {out_path} ({len(output_lines)} hashes; primary format: {primary_name}, hashcat mode {primary_mode})\n"
        f"{f'Skipped {unknown_hashes} row(s) with unrecognized hash format.' if unknown_hashes else ''}\n\n"
        f"Run locally — does NOT touch your site:\n"
        f"  hashcat -m {primary_mode} {out_path.name} /path/to/rockyou.txt\n"
        f"  hashcat -m {primary_mode} {out_path.name} /path/to/rockyou.txt --show     # see cracked hashes\n"
        f"  hashcat -m {primary_mode} {out_path.name} -a 3 ?l?l?l?l?l?l?l?l            # mask attack: 8 lowercase\n\n"
        f"Get hashcat: https://hashcat.net/hashcat/\n"
        f"Get rockyou wordlist: https://github.com/brannondorsey/naive-hashcat/releases\n"
    )

    return {
        "hash_count": len(output_lines),
        "unknown_hashes": unknown_hashes,
        "output_path": str(out_path),
        "primary_mode": primary_mode,
        "primary_name": primary_name,
        "mode_counts": mode_counts,
        "instructions": instructions,
    }
