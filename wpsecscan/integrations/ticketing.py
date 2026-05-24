"""Round-60 #20 — file findings as tickets in Jira / Linear / GitHub Issues.

Each integration takes a finding + a project key. No-op without env-var
credentials. Returns the issue URL on success or "" on failure.

Env vars:
  JIRA_BASE_URL + JIRA_EMAIL + JIRA_TOKEN     — Atlassian
  LINEAR_TOKEN                                  — Linear
  GH_TOKEN                                      — GitHub (or use existing gh CLI auth)
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request
from urllib.error import HTTPError, URLError


def _post_json(url: str, body: dict, *, headers: dict, timeout: float = 15.0) -> dict | None:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                  method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def _finding_body(finding: dict, target: str) -> str:
    return (
        f"**Target:** {target}\n"
        f"**Severity:** {finding.get('severity', '?')}\n"
        f"**URL:** {finding.get('url', '?')}\n\n"
        f"**Evidence**\n```\n{(finding.get('evidence') or '')[:2000]}\n```\n\n"
        f"**Remediation**\n{(finding.get('remediation') or '')[:2000]}\n\n"
        f"_Filed automatically by WPSecScan._"
    )


def jira_create(project_key: str, finding: dict, target: str) -> str:
    base = os.environ.get("JIRA_BASE_URL", "").rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "")
    token = os.environ.get("JIRA_TOKEN", "")
    if not all((base, email, token, project_key)):
        return ""
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    payload = {
        "fields": {
            "project":   {"key": project_key},
            "summary":   (finding.get("title") or "")[:255],
            "description": _finding_body(finding, target),
            "issuetype": {"name": "Bug"},
        },
    }
    d = _post_json(
        f"{base}/rest/api/3/issue", payload,
        headers={"Authorization": f"Basic {auth}",
                  "Content-Type": "application/json",
                  "User-Agent": "WPSecScan/ticketing/jira"},
    )
    return f"{base}/browse/{d['key']}" if d and d.get("key") else ""


def linear_create(team_id: str, finding: dict, target: str) -> str:
    token = os.environ.get("LINEAR_TOKEN", "")
    if not token or not team_id:
        return ""
    mutation = {
        "query": (
            "mutation IssueCreate($input: IssueCreateInput!) {"
            "  issueCreate(input: $input) { success issue { id identifier url } }"
            "}"
        ),
        "variables": {"input": {
            "teamId": team_id,
            "title": (finding.get("title") or "")[:255],
            "description": _finding_body(finding, target),
        }},
    }
    d = _post_json(
        "https://api.linear.app/graphql", mutation,
        headers={"Authorization": token, "Content-Type": "application/json",
                  "User-Agent": "WPSecScan/ticketing/linear"},
    )
    if d and d.get("data", {}).get("issueCreate", {}).get("success"):
        return d["data"]["issueCreate"]["issue"].get("url", "")
    return ""


def github_issue_create(repo: str, finding: dict, target: str) -> str:
    """repo is 'owner/name'. Uses GH_TOKEN env var (or installed gh CLI)."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    if not token or not repo or "/" not in repo:
        return ""
    payload = {
        "title": (finding.get("title") or "")[:255],
        "body":  _finding_body(finding, target),
        "labels": ["security", "wpsecscan", finding.get("severity") or "info"],
    }
    d = _post_json(
        f"https://api.github.com/repos/{repo}/issues", payload,
        headers={"Authorization": f"Bearer {token}",
                  "Accept": "application/vnd.github+json",
                  "User-Agent": "WPSecScan/ticketing/github"},
    )
    return d.get("html_url", "") if d else ""


def file_everywhere(finding: dict, target: str, *,
                      jira_project: str = "", linear_team: str = "",
                      github_repo: str = "") -> dict:
    """One-shot: file the finding in every configured ticketing system."""
    return {
        "jira":   jira_create(jira_project, finding, target) if jira_project else "",
        "linear": linear_create(linear_team, finding, target) if linear_team else "",
        "github": github_issue_create(github_repo, finding, target) if github_repo else "",
    }
