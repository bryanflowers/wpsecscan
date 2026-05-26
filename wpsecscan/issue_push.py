"""Item #35 — direct REST push to Jira / Linear / ServiceNow / GitHub Issues.

The existing reporters.issue_export emits curl scripts the user runs by
hand. This module performs the actual REST push and tracks ticket IDs in
~/.wpsecscan/issue-tracker-cache.json so re-scans don't create duplicate
tickets for the same (target, check_id, finding_title) tuple.

Idempotency: every payload is keyed by sha256(target + ":" + check_id +
"::" + finding_title). The cache stores
  {key: {"system": "jira", "ticket_id": "SEC-42", "url": "...", "created": "..."}}
which the GUI / CLI / reporters can surface as "Tracked in Jira SEC-42".

All tokens are read from environment variables — never from a CLI arg —
so they don't appear in `ps aux` or shell history.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path
from urllib.error import HTTPError, URLError


def _cache_path() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    return home / "issue-tracker-cache.json"


def _load_cache() -> dict[str, dict]:
    p = _cache_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict[str, dict]) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass


def idempotency_key(target: str, check_id: str, finding_title: str) -> str:
    """sha256 of the (target, check_id, finding_title) tuple — used to
    deduplicate ticket creation across rescans."""
    raw = f"{target}|{check_id}|{finding_title}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _post_json(url: str, body: dict, headers: dict, timeout: float = 20.0) -> tuple[int, dict | None]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                   headers={"Content-Type": "application/json",
                                            "User-Agent": "WPSecScan/issue-push",
                                            **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------

def push_jira(target: str, payloads: list[dict], *, base_url: str, email: str,
              cache: dict[str, dict] | None = None) -> list[dict]:
    """POST each payload to {base}/rest/api/2/issue. Token via $JIRA_API_TOKEN."""
    token = os.environ.get("JIRA_API_TOKEN") or os.environ.get("WPSECSCAN_JIRA_TOKEN", "")
    if not token:
        return [{"ok": False, "error": "JIRA_API_TOKEN not set"}]
    import base64
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    cache = cache if cache is not None else _load_cache()
    results = []
    for p in payloads:
        title = (p.get("fields") or {}).get("summary", "")
        # The Jira payload doesn't carry check_id structurally; use empty cid
        # so the key is stable across reschedules (target + title is enough
        # for dedup in practice).
        key = idempotency_key(target, "", title)
        if key in cache:
            results.append({"ok": True, "skipped": True, "ticket": cache[key].get("ticket_id"),
                              "url": cache[key].get("url")})
            continue
        status, body = _post_json(
            f"{base_url.rstrip('/')}/rest/api/2/issue",
            p,
            {"Authorization": f"Basic {auth}"},
        )
        if status in (200, 201) and isinstance(body, dict) and body.get("key"):
            ticket_id = body["key"]
            ticket_url = f"{base_url.rstrip('/')}/browse/{ticket_id}"
            cache[key] = {"system": "jira", "ticket_id": ticket_id, "url": ticket_url,
                          "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            results.append({"ok": True, "ticket": ticket_id, "url": ticket_url})
        else:
            results.append({"ok": False, "status": status, "error": body})
    _save_cache(cache)
    return results


# ---------------------------------------------------------------------------
# Linear
# ---------------------------------------------------------------------------

def push_linear(target: str, payloads: list[dict],
                 cache: dict[str, dict] | None = None) -> list[dict]:
    """POST each GraphQL payload to api.linear.app/graphql. Token via $LINEAR_API_KEY."""
    token = os.environ.get("LINEAR_API_KEY") or os.environ.get("WPSECSCAN_LINEAR_TOKEN", "")
    if not token:
        return [{"ok": False, "error": "LINEAR_API_KEY not set"}]
    cache = cache if cache is not None else _load_cache()
    results = []
    for p in payloads:
        title = (p.get("variables") or {}).get("input", {}).get("title", "")
        cid = ""  # Linear payloads don't carry check_id in a structured field
        key = idempotency_key(target, cid, title)
        if key in cache:
            results.append({"ok": True, "skipped": True,
                              "ticket": cache[key].get("ticket_id"),
                              "url": cache[key].get("url")})
            continue
        status, body = _post_json(
            "https://api.linear.app/graphql",
            p,
            {"Authorization": token},
        )
        if status == 200 and isinstance(body, dict):
            issue = (((body.get("data") or {}).get("issueCreate") or {})
                       .get("issue") or {})
            if issue.get("identifier"):
                cache[key] = {"system": "linear", "ticket_id": issue["identifier"],
                              "url": issue.get("url", ""),
                              "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                results.append({"ok": True, "ticket": issue["identifier"], "url": issue.get("url")})
                continue
        results.append({"ok": False, "status": status, "error": body})
    _save_cache(cache)
    return results


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------

def servicenow_payloads(report, min_sev: str = "high") -> list[dict]:
    """Build ServiceNow incident records (table=incident). The instance URL
    and basic-auth come from env at push time."""
    from .reporters.issue_export import _top_findings, _markdown_body
    out = []
    sev_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    for cid, f in _top_findings(report, min_sev):
        out.append({
            "short_description": f"[WPSecScan] [{f.severity.upper()}] {f.title[:120]}",
            "description": _markdown_body(cid, f),
            "category": "security",
            "priority": str(sev_map.get(f.severity, 4)),
            "impact": str(sev_map.get(f.severity, 4)),
            "urgency": str(sev_map.get(f.severity, 4)),
            "wpsecscan_check_id": cid,  # custom field; ignored if not configured
            "wpsecscan_finding_title": f.title,
        })
    return out


def push_servicenow(target: str, payloads: list[dict], *, instance: str,
                     cache: dict[str, dict] | None = None) -> list[dict]:
    """instance like 'mycompany.service-now.com'.
    Auth: $SERVICENOW_USERNAME + $SERVICENOW_PASSWORD."""
    user = os.environ.get("SERVICENOW_USERNAME", "")
    pwd  = os.environ.get("SERVICENOW_PASSWORD", "")
    if not user or not pwd:
        return [{"ok": False, "error": "SERVICENOW_USERNAME / SERVICENOW_PASSWORD not set"}]
    import base64
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    cache = cache if cache is not None else _load_cache()
    results = []
    for p in payloads:
        title = p.get("short_description", "")
        cid = p.get("wpsecscan_check_id", "")
        key = idempotency_key(target, cid, p.get("wpsecscan_finding_title", title))
        if key in cache:
            results.append({"ok": True, "skipped": True,
                              "ticket": cache[key].get("ticket_id"),
                              "url": cache[key].get("url")})
            continue
        status, body = _post_json(
            f"https://{instance}/api/now/table/incident",
            p,
            {"Authorization": f"Basic {auth}", "Accept": "application/json"},
        )
        if status in (200, 201) and isinstance(body, dict):
            rec = (body.get("result") or {})
            if rec.get("number"):
                cache[key] = {"system": "servicenow", "ticket_id": rec["number"],
                              "url": f"https://{instance}/nav_to.do?uri=incident.do?sys_id={rec.get('sys_id','')}",
                              "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                results.append({"ok": True, "ticket": rec["number"], "url": cache[key]["url"]})
                continue
        results.append({"ok": False, "status": status, "error": body})
    _save_cache(cache)
    return results


# ---------------------------------------------------------------------------
# GitHub Issues
# ---------------------------------------------------------------------------

def push_github(target: str, payloads: list[dict], *, repo: str,
                 cache: dict[str, dict] | None = None) -> list[dict]:
    """repo = 'owner/name'. Token via $GITHUB_TOKEN."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("WPSECSCAN_GITHUB_TOKEN", "")
    if not token:
        return [{"ok": False, "error": "GITHUB_TOKEN not set"}]
    cache = cache if cache is not None else _load_cache()
    results = []
    for p in payloads:
        title = p.get("title", "")
        cid = ""  # GH payloads don't carry check_id structurally
        key = idempotency_key(target, cid, title)
        if key in cache:
            results.append({"ok": True, "skipped": True,
                              "ticket": cache[key].get("ticket_id"),
                              "url": cache[key].get("url")})
            continue
        status, body = _post_json(
            f"https://api.github.com/repos/{repo}/issues",
            p,
            {"Authorization": f"Bearer {token}",
             "Accept": "application/vnd.github+json"},
        )
        if status in (200, 201) and isinstance(body, dict) and body.get("number"):
            cache[key] = {"system": "github", "ticket_id": f"#{body['number']}",
                          "url": body.get("html_url", ""),
                          "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            results.append({"ok": True, "ticket": f"#{body['number']}",
                              "url": body.get("html_url")})
        else:
            results.append({"ok": False, "status": status, "error": body})
    _save_cache(cache)
    return results
