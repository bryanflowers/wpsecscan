"""GitHub Issues integration — opt-in auto-create for critical/high findings.

The user provides a repo (`owner/repo`) and a PAT with `issues:write` scope
in the Settings dialog. After a scan, one issue is created per finding ≥ the
chosen threshold, with severity labels and full evidence/remediation body.

Defensive: only POSTs to https://api.github.com. URL validated.
"""
from __future__ import annotations

import json
import re
import urllib.request
from urllib.error import HTTPError, URLError

API_BASE = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_repo(repo: str) -> tuple[bool, str]:
    if not repo or not isinstance(repo, str):
        return False, "repo is empty"
    if not REPO_RE.match(repo):
        return False, f"repo must look like `owner/repo`, got {repo!r}"
    return True, ""


def _post_issue(repo: str, token: str, title: str, body: str, labels: list[str],
                timeout: float = 8.0) -> tuple[bool, str]:
    url = f"{API_BASE}/repos/{repo}/issues"
    payload = {"title": title, "body": body, "labels": labels}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "WPSecScan/github-issues",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if 200 <= resp.status < 300:
                d = json.loads(resp.read().decode("utf-8", "replace"))
                return True, d.get("html_url", "")
            return False, f"HTTP {resp.status}"
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.read()[:200].decode('utf-8', 'replace')}"
    except (URLError, OSError, ValueError) as e:
        return False, str(e)


def _build_body(report, check_id: str, check_name: str, f) -> str:
    """Format the issue body in GitHub-flavoured markdown."""
    from .. import tags as _tags
    tg = _tags.get_tags(check_id) or {}
    cm = _tags.get_compliance(check_id) or {}
    lines: list[str] = [
        f"**Severity**: {f.severity.upper()}",
        f"**Check**: `{check_id}` ({check_name})",
        f"**URL**: {f.url}" if f.url else "",
        f"**Scanned at**: {report.scanned_at}",
        "",
        "## Evidence",
        "",
        "````",
        (f.evidence or "(no evidence)")[:4000],
        "````",
        "",
        "## Remediation",
        "",
        f.remediation or "(see findings docs)",
        "",
        "## Tags",
        "",
    ]
    if tg.get("owasp"):
        lines.append(f"- OWASP: `{tg['owasp']}` — {tg.get('owasp_label','')}")
    if tg.get("attack"):
        lines.append(f"- MITRE ATT&CK: `{tg['attack']}` — {tg.get('attack_label','')}")
    if cm.get("pci_dss") and cm["pci_dss"] != "n/a":
        lines.append(f"- PCI-DSS: `{cm['pci_dss']}`")
    if cm.get("nist_800_53") and cm["nist_800_53"] != "n/a":
        lines.append(f"- NIST 800-53: `{cm['nist_800_53']}`")
    if cm.get("iso_27001") and cm["iso_27001"] != "n/a":
        lines.append(f"- ISO 27001: `{cm['iso_27001']}`")
    lines += ["", "---", "*Filed automatically by WPSecScan*"]
    return "\n".join([line for line in lines if line is not None])


def create_issues_for_report(report, repo: str, token: str, threshold: str = "high") -> dict:
    """Walk the report; POST a GitHub Issue for every finding >= threshold.

    Returns a summary dict: {ok: N, fail: N, urls: [...], errors: [...]}.
    """
    ok_repo, why = validate_repo(repo)
    if not ok_repo:
        return {"ok": 0, "fail": 0, "errors": [why], "urls": []}
    if not token:
        return {"ok": 0, "fail": 0, "errors": ["no token provided"], "urls": []}
    rank_threshold = SEVERITY_RANK.get(threshold, 3)
    created_urls: list[str] = []
    errors: list[str] = []
    for r in report.results:
        if r.error:
            continue
        for f in r.findings:
            if SEVERITY_RANK.get(f.severity, 0) < rank_threshold:
                continue
            # Mark titles that exceed GitHub's 256-char limit so the user knows it was clipped.
            if len(f.title) > 200:
                title = f"[{f.severity.upper()}] {f.title[:197]}..."
            else:
                title = f"[{f.severity.upper()}] {f.title}"
            body = _build_body(report, r.check_id, r.check_name, f)
            labels = [f"severity:{f.severity}", "wpsecscan", f"check:{r.check_id}"]
            ok, url_or_err = _post_issue(repo, token, title, body, labels)
            if ok:
                created_urls.append(url_or_err)
            else:
                errors.append(f"{title[:80]} -> {url_or_err}")
    return {"ok": len(created_urls), "fail": len(errors), "urls": created_urls, "errors": errors}
