"""#21 (from ZAP / DirBuster) — forced-browse / hidden-path discovery.

Fans out a 200-entry curated wordlist (data/common_paths.txt) against the
target's web root. Anything that returns 200 / 301 / 302 with a non-trivial
body is reported as a discovered path the homepage didn't link to.

User can extend the wordlist by dropping additional lines into
~/.wpsecscan/extra_paths.txt — those are merged at load time.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from ..http import Client
from ..models import Finding


def _builtin_paths() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data" / "common_paths.txt"
    return Path(__file__).resolve().parent.parent / "data" / "common_paths.txt"


def _user_paths() -> Path:
    from .. import history as _h
    return Path(_h._home()) / "extra_paths.txt"


def _load_wordlist() -> list[str]:
    paths: set[str] = set()
    for p in (_builtin_paths(), _user_paths()):
        if not p.exists():
            continue
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "*" in line:
                    continue
                paths.add(line.lstrip("/"))
        except OSError:
            continue
    return sorted(paths)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    paths = _load_wordlist()
    if not paths:
        return [Finding(severity="info", title="Forced-browse: empty wordlist",
                        evidence="data/common_paths.txt not readable.",
                        remediation="No action.", url=ctx["target"])]

    step(f"forced-browse: probing {len(paths)} paths...")
    sem = asyncio.Semaphore(6)

    async def _probe(path: str):
        async with sem:
            try:
                r = await client.head("/" + path)
            except Exception:  # noqa: BLE001
                return None
            return (path, r) if r is not None else None

    raw = await asyncio.gather(*(_probe(p) for p in paths))
    hits: list[tuple[str, int, int]] = []
    for entry in raw:
        if not entry:
            continue
        path, r = entry
        if r.status_code in (200, 201, 301, 302, 401, 403):
            size = int(r.headers.get("content-length", 0) or 0)
            # 403 still reported — that's an "exists but forbidden" leak
            hits.append((path, r.status_code, size))

    if not hits:
        findings.append(Finding(
            severity="info",
            title=f"Forced-browse: clean ({len(paths)} paths probed)",
            evidence="No hidden paths returned 200/301/302/401/403.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Bucket by severity: critical for the obvious wins, medium for the rest
    critical_keywords = {"wp-config", ".env", ".git", "database.sql", "backup.sql",
                          "phpinfo", "adminer", "phpmyadmin", "debug.log"}

    crit_hits = [(p, s, sz) for p, s, sz in hits if any(k in p for k in critical_keywords) and s != 403]
    other_hits = [(p, s, sz) for p, s, sz in hits if (p, s, sz) not in crit_hits]

    if crit_hits:
        findings.append(Finding(
            severity="critical",
            title=f"Forced-browse: {len(crit_hits)} CRITICAL hidden path(s) reachable",
            evidence="\n".join(f"  - /{p} HTTP {s} ({sz} bytes)" for p, s, sz in crit_hits),
            remediation=(
                "Block these paths immediately. Nginx pattern:\n"
                "  location ~ /(wp-config|\\.env|\\.git|phpinfo|adminer|phpmyadmin) { deny all; }"
            ),
            url=ctx["target"],
        ))
    if other_hits:
        sev = "medium" if len(other_hits) > 5 else "low"
        findings.append(Finding(
            severity=sev,
            title=f"Forced-browse: {len(other_hits)} other discovered path(s)",
            evidence="\n".join(f"  - /{p} HTTP {s}" for p, s, _z in other_hits[:25])
                     + (f"\n  ... and {len(other_hits) - 25} more" if len(other_hits) > 25 else ""),
            remediation=(
                "Review each — paths that should be public (like /robots.txt) are fine to "
                "leave; private ones (admin panels, backup dirs) should be blocked or require auth."
            ),
            url=ctx["target"],
        ))
    return findings
