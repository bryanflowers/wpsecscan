"""Exploit playbook loader.

Each entry in data/exploit_playbook.json maps a check_id to a dict of
attacker-tool buckets (curl / sqlmap / metasploit / nuclei / wpscan /
references). Reporters look up by check_id and render only the non-empty
sections — entries without a playbook are silently skipped.

Commands contain {target} and {host} placeholders that are substituted
at render time, same convention as quick_fixes.json's `verify` section.

Defensive use only: the commands probe the user's OWN sites for
proof-of-impact, they don't auto-exploit. wpsecscan never executes any
of these — they're text the user copies into their own terminal.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

# Bucket field-names recognised by reporters, in the order they should display.
# Anything not in this list (e.g. "_section", "_meta") is ignored.
BUCKET_ORDER = (
    "how_an_attacker_uses_this",
    "manual_curl_pocs",
    "sqlmap",
    "metasploit",
    "wpscan",
    "nuclei",
    "ffuf_gobuster",
    "references",
)

BUCKET_LABEL = {
    "how_an_attacker_uses_this": "How an attacker uses this",
    "manual_curl_pocs": "Manual probe (curl)",
    "sqlmap": "sqlmap",
    "metasploit": "Metasploit",
    "wpscan": "wpscan",
    "nuclei": "nuclei",
    "ffuf_gobuster": "ffuf / gobuster",
    "references": "References",
}


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent / "data"


_CACHE: dict | None = None


def _load() -> dict:
    """Read and cache the playbook JSON. Returns {} on any I/O or parse error."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    f = _data_dir() / "exploit_playbook.json"
    if not f.exists():
        _CACHE = {}
        return _CACHE
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        # Drop the _meta and _schema documentation entries.
        _CACHE = {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)}
    except (OSError, json.JSONDecodeError):
        _CACHE = {}
    return _CACHE


def get_playbook(check_id: str) -> dict | None:
    """Return the raw (unsubstituted) playbook dict for a check_id, or None."""
    return _load().get(check_id)


def reset_cache() -> None:
    """Force the next get_playbook() call to re-read the JSON. For tests."""
    global _CACHE
    _CACHE = None


def _substitute_one(template: str, target: str) -> str:
    """Substitute {target} and {host} in a single command string."""
    host = urlparse(target).hostname or target
    return template.replace("{target}", target.rstrip("/")).replace("{host}", host)


def substitute(playbook: dict, target: str) -> dict:
    """Return a copy of the playbook with {target}/{host} substituted in all string values."""
    out: dict = {}
    for k, v in playbook.items():
        if isinstance(v, str):
            out[k] = _substitute_one(v, target)
        elif isinstance(v, list):
            out[k] = [_substitute_one(item, target) if isinstance(item, str) else item for item in v]
        else:
            out[k] = v
    return out


def ordered_buckets(playbook: dict) -> list[tuple[str, str, list[str] | str]]:
    """Return [(field_name, display_label, content), ...] in display order, skipping empties.

    For the prose field `how_an_attacker_uses_this`, content is a str.
    For all other buckets, content is a list[str].
    """
    out: list = []
    for field in BUCKET_ORDER:
        v = playbook.get(field)
        if not v:
            continue
        if field == "how_an_attacker_uses_this" and isinstance(v, str):
            out.append((field, BUCKET_LABEL[field], v))
        elif isinstance(v, list) and v:
            out.append((field, BUCKET_LABEL[field], list(v)))
    return out
