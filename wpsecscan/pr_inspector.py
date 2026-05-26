"""Item #36 — GitHub PR auto-commenter for plugin/theme touch-ups.

Inspects a GitHub PR's file list. For every changed file under
`wp-content/plugins/<slug>/` or `wp-content/themes/<slug>/`, looks up
that slug against the local Wordfence/Patchstack CVE DB (via the
existing `wpsecscan.db` module) and posts ONE summary comment on the
PR listing currently-open CVEs for those plugins.

Uses the user's existing PAT (env: $GITHUB_TOKEN) — no new GitHub App
registration required. Idempotency: each comment is signed with a
`<!-- wpsecscan-pr-comment -->` HTML marker; the script searches
existing comments and updates the marker'd one instead of duplicating.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse


_MARKER = "<!-- wpsecscan-pr-comment -->"

_PLUGIN_RE = re.compile(r"^wp-content/plugins/([a-z0-9][a-z0-9\-_]+)/", re.IGNORECASE)
_THEME_RE  = re.compile(r"^wp-content/themes/([a-z0-9][a-z0-9\-_]+)/",  re.IGNORECASE)


def _parse_pr_url(url: str) -> tuple[str, str, int] | None:
    """`https://github.com/owner/repo/pull/123` → ('owner', 'repo', 123)."""
    u = urlparse(url)
    if u.netloc not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 4 or parts[2] != "pull":
        return None
    try:
        return parts[0], parts[1], int(parts[3])
    except ValueError:
        return None


def _gh(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict | list | None]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        data=data, method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "WPSecScan/pr-inspector",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20.0) as r:
            raw = r.read().decode("utf-8", errors="replace")
            try:
                return r.status, json.loads(raw) if raw else None
            except ValueError:
                return r.status, None
    except HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            err_body = ""
        return e.code, {"error": err_body[:500]}
    except (URLError, OSError) as e:
        return 0, {"error": str(e)}


def list_changed_slugs(owner: str, repo: str, pr: int, token: str) -> dict[str, list[str]]:
    """Return {"plugins": [slug, ...], "themes": [slug, ...]}.

    Walks every page of the PR's file list."""
    plugins: set[str] = set()
    themes: set[str] = set()
    page = 1
    while True:
        status, body = _gh("GET", f"/repos/{owner}/{repo}/pulls/{pr}/files?per_page=100&page={page}",
                             token)
        if status != 200 or not isinstance(body, list) or not body:
            break
        for f in body:
            filename = f.get("filename", "")
            m = _PLUGIN_RE.match(filename)
            if m:
                plugins.add(m.group(1).lower())
            m = _THEME_RE.match(filename)
            if m:
                themes.add(m.group(1).lower())
        if len(body) < 100:
            break
        page += 1
    return {"plugins": sorted(plugins), "themes": sorted(themes)}


def find_known_cves(plugins: list[str], themes: list[str]) -> list[dict]:
    """Cross-reference slugs against the local CVE DB. Returns
    [{slug, type, cves: [{cve_id, severity, fixed_in}, ...]}, ...]."""
    try:
        from . import db as _db
    except ImportError:
        return []
    out: list[dict] = []
    for slug in plugins:
        cves = _db.lookup_by_slug(slug, kind="plugin") if hasattr(_db, "lookup_by_slug") else []
        if cves:
            out.append({"slug": slug, "type": "plugin", "cves": cves})
    for slug in themes:
        cves = _db.lookup_by_slug(slug, kind="theme") if hasattr(_db, "lookup_by_slug") else []
        if cves:
            out.append({"slug": slug, "type": "theme", "cves": cves})
    return out


def build_comment(touched: dict[str, list[str]], findings: list[dict]) -> str:
    lines = [_MARKER, "## 🔍 WPSecScan PR review", ""]
    plugins = touched.get("plugins") or []
    themes = touched.get("themes") or []
    if not (plugins or themes):
        lines.append("No WordPress plugins or themes touched by this PR — no CVE check needed.")
        return "\n".join(lines)
    lines.append(f"This PR touches **{len(plugins)} plugin(s)** and "
                  f"**{len(themes)} theme(s)** in `wp-content/`.\n")
    if not findings:
        lines.append("✅ No currently-open CVEs match the touched slugs in the WPSecScan DB.")
    else:
        lines.append(f"⚠️ **{len(findings)} touched slug(s) have currently-open CVEs:**")
        lines.append("")
        lines.append("| Slug | Type | Open CVEs |")
        lines.append("|------|------|-----------|")
        for f in findings:
            cves = f.get("cves") or []
            ids = ", ".join(c.get("cve_id", "") for c in cves[:5])
            if len(cves) > 5:
                ids += f" (+{len(cves) - 5} more)"
            lines.append(f"| `{f['slug']}` | {f['type']} | {ids} |")
        lines.append("")
        lines.append("Run `wpsecscan SITE_URL --md` against any deployed environment "
                      "to confirm whether the running version is affected.")
    lines.append("")
    lines.append("<sub>generated by wpsecscan pr-comment · "
                  "see https://github.com/bryanflowers/wpsecscan</sub>")
    return "\n".join(lines)


def find_existing_marker_comment(owner: str, repo: str, pr: int,
                                    token: str) -> int | None:
    """Return the comment ID of an existing WPSecScan PR comment, if any."""
    status, body = _gh("GET", f"/repos/{owner}/{repo}/issues/{pr}/comments?per_page=100",
                          token)
    if status != 200 or not isinstance(body, list):
        return None
    for c in body:
        if _MARKER in (c.get("body") or ""):
            try:
                return int(c.get("id"))
            except (TypeError, ValueError):
                continue
    return None


def post_or_update(owner: str, repo: str, pr: int, token: str, body: str) -> tuple[bool, str]:
    """Update an existing marker-comment, else post a new one.
    Returns (ok, message)."""
    existing = find_existing_marker_comment(owner, repo, pr, token)
    if existing:
        status, resp = _gh("PATCH",
                             f"/repos/{owner}/{repo}/issues/comments/{existing}",
                             token, {"body": body})
        if status in (200, 201):
            return True, f"updated comment id={existing}"
        return False, f"PATCH failed status={status} body={resp}"
    status, resp = _gh("POST",
                         f"/repos/{owner}/{repo}/issues/{pr}/comments",
                         token, {"body": body})
    if status in (200, 201) and isinstance(resp, dict):
        return True, f"new comment id={resp.get('id')} url={resp.get('html_url')}"
    return False, f"POST failed status={status} body={resp}"
