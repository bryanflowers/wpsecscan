"""#2 (from wpscan) — plugin file-hash → version fingerprinting.

When `readme.txt` is stripped (a common hardening step), the standard plugin
version-detection path fails. But static files (CSS / JS / image bundles)
usually still ship verbatim per plugin release. We hash those files and
match against a curated hash → version map.

Hash format: sha256(body_bytes), first 16 hex chars (64-bit) — enough to
avoid collisions for our purposes, short enough to keep the JSON small.

User can extend the shipped map via ~/.wpsecscan/plugin_hashes.json.
"""
from __future__ import annotations

import hashlib
import json
import sys
from functools import lru_cache
from pathlib import Path

from ..http import Client
from ..models import Finding


def _builtin_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data" / "plugin_file_hashes.json"
    return Path(__file__).resolve().parent.parent / "data" / "plugin_file_hashes.json"


def _user_path() -> Path:
    from .. import history as _h
    return Path(_h._home()) / "plugin_hashes.json"


@lru_cache(maxsize=1)
def _load_map() -> dict:
    """Merge built-in map with user overrides; user wins on conflict."""
    out: dict = {}
    try:
        out.update(json.loads(_builtin_path().read_text(encoding="utf-8")) or {})
    except (OSError, ValueError):
        pass
    up = _user_path()
    if up.exists():
        try:
            user = json.loads(up.read_text(encoding="utf-8")) or {}
            for k, v in user.items():
                if isinstance(v, dict):
                    base = dict(out.get(k) or {})
                    base.update(v)
                    out[k] = base
        except (OSError, ValueError):
            pass
    # Strip schema sections that aren't path keys
    return {k: v for k, v in out.items() if isinstance(v, dict) and "/" in k}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    hash_map = _load_map()
    if not hash_map:
        findings.append(Finding(
            severity="info",
            title="Plugin file-hash fingerprint — no hash map loaded",
            evidence="Built-in map empty + no ~/.wpsecscan/plugin_hashes.json. Drop a JSON to extend.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Use plugins detected by the plugins check, or fall back to probing every slug
    shared = ctx.get("shared") or {}
    plugins = shared.get("plugins") or []
    known_slugs = {p.get("slug") for p in plugins if isinstance(p, dict) and p.get("slug")}

    hits: list[tuple[str, str, str, str]] = []  # (slug, file, version, hash_prefix)
    matched_paths = 0

    for path_key, version_map in hash_map.items():
        slug = path_key.split("/", 1)[0]
        if known_slugs and slug not in known_slugs:
            # When we already know the slugs, skip files for plugins we know aren't installed
            continue
        file_path = "/wp-content/plugins/" + path_key
        step(f"hash-fingerprint {path_key}...")
        r = await client.get(file_path)
        if r is None or r.status_code != 200 or not r.content:
            continue
        matched_paths += 1
        h = hashlib.sha256(r.content).hexdigest()[:16]
        for hash_prefix, version in version_map.items():
            if h == hash_prefix:
                hits.append((slug, path_key, version, hash_prefix))
                break

    if not hits:
        findings.append(Finding(
            severity="info",
            title=f"Plugin file-hash fingerprint — no version matches ({matched_paths} files fetched)",
            evidence=("Hashed every reachable plugin file in the map; none matched a known release. "
                       "Either every installed plugin is custom-built / private, or all "
                       "are at versions newer than the shipped map. Consider contributing your "
                       "release hashes back upstream."),
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    findings.append(Finding(
        severity="info",
        title=f"Plugin versions inferred from file hashes ({len(hits)} match(es))",
        evidence="\n".join(f"  - {s} {v}  (file: {f}, hash prefix {h})" for s, f, v, h in hits) + (
            "\n\nThis works even when readme.txt has been removed for hardening. "
            "The version informs subsequent CVE matching."),
        remediation=(
            "If you stripped readme.txt to hide the version, also strip / fingerprint-bust "
            "the asset bundles — change a few bytes in the minified CSS so the hash differs. "
            "Or accept that obscurity isn't real defence and focus on patching to the latest."
        ),
        url=ctx["target"],
    ))

    # Surface inferred versions into shared so plugin_cves can use them
    shared.setdefault("inferred_plugin_versions", {})
    for slug, _f, version, _h in hits:
        shared["inferred_plugin_versions"][slug] = version

    return findings
