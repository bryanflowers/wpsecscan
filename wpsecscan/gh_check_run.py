"""Item #62 — GitHub Check Run status: wpsecscan-as-required-status.

The existing `wpsecscan pr-comment` (round-44) posts a *comment* to a PR.
A Check Run is different: it surfaces as a status next to "All checks
passing" on the PR page, and branch-protection rules can *require* a
specific check to pass before merge. That's a security gate, not just
chatter.

POSTs to `/repos/{owner}/{repo}/check-runs` with the running scan's
overall verdict:

  conclusion = "success"       — no findings at or above fail-on level
  conclusion = "failure"       — fail-on threshold met or exceeded
  conclusion = "neutral"       — no fail-on configured; summary only

Needs $GITHUB_TOKEN with `checks:write` (or repo scope). Operator
supplies the commit SHA — we don't try to infer from a PR URL because
the PR's head SHA changes on every push and we want this to attach to
the SHA we actually scanned.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from .models import ScanReport


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _conclusion(report: ScanReport, fail_on: str) -> tuple[str, str]:
    """Return (conclusion, title) for the check run."""
    threshold = _SEV_RANK.get((fail_on or "").lower())
    if threshold is None:
        return "neutral", f"WPSecScan: score {report.risk_score}/100"
    worst = max((_SEV_RANK.get(f.severity, -1) for f in report.all_findings),
                 default=-1)
    if worst >= threshold:
        worst_label = report.worst_severity() or ""
        return "failure", f"WPSecScan: {worst_label.upper()} finding(s) at/above {fail_on}"
    return "success", f"WPSecScan: clean at >= {fail_on} (score {report.risk_score}/100)"


def _summary_md(report: ScanReport) -> str:
    s = report.summary
    return (
        f"**Risk score:** {report.risk_score} / 100\n\n"
        f"| Severity | Count |\n|---|---|\n"
        f"| Critical | {s.get('critical', 0)} |\n"
        f"| High     | {s.get('high', 0)} |\n"
        f"| Medium   | {s.get('medium', 0)} |\n"
        f"| Low      | {s.get('low', 0)} |\n"
        f"| Info     | {s.get('info', 0)} |\n\n"
        f"Target: `{report.target}`\n"
        f"Scanned at: `{report.scanned_at}`\n"
    )


def post_check_run(report: ScanReport, owner: str, repo: str, head_sha: str,
                    *, token: str | None = None, fail_on: str = "high",
                    name: str = "wpsecscan") -> dict[str, Any]:
    """Create a Check Run on the given commit SHA. Returns the API response."""
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("WPSECSCAN_GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("set $GITHUB_TOKEN (or $WPSECSCAN_GITHUB_TOKEN) with checks:write scope")
    conclusion, title = _conclusion(report, fail_on)
    payload = {
        "name": name,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": _summary_md(report),
        },
    }
    with httpx.Client(timeout=15.0,
                       headers={"User-Agent": "WPSecScan-CheckRun/1.0",
                                "Authorization": f"Bearer {token}",
                                "Accept": "application/vnd.github+json",
                                "X-GitHub-Api-Version": "2022-11-28"}) as c:
        r = c.post(f"https://api.github.com/repos/{owner}/{repo}/check-runs",
                    json=payload)
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub {r.status_code}: {r.text[:300]}")
        return r.json()
