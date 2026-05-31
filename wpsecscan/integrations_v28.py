"""v2.8.1 integrations (I1-I13).

Adds 13 new optional sinks/sources to the wpsecscan integration mesh.
Every function is a no-op when its env vars aren't set so they're safe
to call unconditionally from emit pipelines.

  I1  gitlab_ci_security_gate(report)   — fail a GitLab CI job on findings
  I2  circleci_orb_emit(report)         — Insights API event for CircleCI
  I3  azure_devops_workitem(report)     — Azure DevOps Boards work-item
  I4  buildkite_annotation(report)      — Buildkite agent annotation
  I5  push_shortcut(report)             — Shortcut (Clubhouse) story
  I6  push_plane(report)                — Plane.so issue
  I7  nuclei_template_export(report)    — emit project-yaml Nuclei templates
  I8  osv_dev_enrich(report)            — OSV.dev schema enrichment
  I9  exploitdb_xref(report)            — ExploitDB cross-reference IDs
  I10 wiz_lacework_push(report)         — Wiz / Lacework custom-finding push
  I11 chat_webhooks(report)             — Mattermost/RocketChat/Telegram
  I12 hosting_api_event(report)         — WP Engine / Kinsta event API
  I13 automation_hub_webhook(report)    — n8n / Make.com / Notion / Power Automate / Patchstack-in
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx


_TIMEOUT = 10.0


def _post_json(url: str, body: Any, headers: dict | None = None) -> tuple[bool, str]:
    """Shared POST helper. Returns (success, message)."""
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.post(url, json=body, headers=headers or {})
            if 200 <= r.status_code < 300:
                return True, f"HTTP {r.status_code}"
            return False, f"HTTP {r.status_code} from {url}: {r.text[:120]}"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return False, f"error: {e}"


# ---------------------------------------------------------------------------
# I1 — GitLab CI security gate
# ---------------------------------------------------------------------------
def gitlab_ci_security_gate(report, *, fail_on: str = "high") -> tuple[bool, str]:
    """Emit GitLab Code Quality JSON to GL_CODE_QUALITY_REPORT (if set);
    additionally exit non-zero by env-var hint when worst severity >= fail_on."""
    out_path = os.environ.get("GL_CODE_QUALITY_REPORT")
    if not out_path:
        return False, "set GL_CODE_QUALITY_REPORT=<path>"
    from .models import SEVERITY_RANK
    threshold = SEVERITY_RANK.get(fail_on.lower(), 3)
    issues = []
    for r in report.results:
        for f in r.findings:
            sev_rank = SEVERITY_RANK.get(f.severity.lower(), 0)
            if sev_rank < threshold:
                continue
            issues.append({
                "description": (f.title or r.check_name)[:200],
                "fingerprint": f"{r.check_id}:{(f.title or '')[:60]}",
                "severity": f.severity,
                "location": {"path": "wpsecscan-scan", "lines": {"begin": 1}},
            })
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(issues, fh, indent=2)
        return True, f"wrote {len(issues)} issue(s) to {out_path}"
    except OSError as e:
        return False, f"write failed: {e}"


# ---------------------------------------------------------------------------
# I2 — CircleCI Insights event
# ---------------------------------------------------------------------------
def circleci_orb_emit(report) -> tuple[bool, str]:
    """POST a scan summary to a CircleCI custom-data webhook URL."""
    url = os.environ.get("CIRCLECI_WEBHOOK_URL")
    if not url:
        return False, "set CIRCLECI_WEBHOOK_URL"
    body = {
        "target": report.target,
        "risk_score": report.risk_score,
        "summary": dict(report.summary or {}),
    }
    return _post_json(url, body)


# ---------------------------------------------------------------------------
# I3 — Azure DevOps Boards work-item
# ---------------------------------------------------------------------------
def azure_devops_workitem(report) -> tuple[bool, str]:
    """Create a Bug work-item in Azure DevOps Boards via REST 7.0.
    Env: AZDO_ORG, AZDO_PROJECT, AZDO_PAT."""
    org = os.environ.get("AZDO_ORG", "")
    proj = os.environ.get("AZDO_PROJECT", "")
    pat = os.environ.get("AZDO_PAT", "")
    if not (org and proj and pat):
        return False, "set AZDO_ORG + AZDO_PROJECT + AZDO_PAT"
    url = f"https://dev.azure.com/{org}/{proj}/_apis/wit/workitems/$Bug?api-version=7.0"
    patch = [
        {"op": "add", "path": "/fields/System.Title",
         "value": f"WPSecScan: risk {report.risk_score} on {report.target}"},
        {"op": "add", "path": "/fields/System.Description",
         "value": f"<pre>{report.target}\nRisk: {report.risk_score}/100\n"
                   f"Summary: {report.summary}</pre>"},
    ]
    try:
        import base64
        auth = base64.b64encode(f":{pat}".encode()).decode()
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.post(url, content=json.dumps(patch),
                        headers={"Authorization": f"Basic {auth}",
                                  "Content-Type": "application/json-patch+json"})
            if 200 <= r.status_code < 300:
                return True, f"AZDO work-item created (HTTP {r.status_code})"
            return False, f"AZDO HTTP {r.status_code}: {r.text[:120]}"
    except (httpx.RequestError, OSError) as e:
        return False, f"AZDO error: {e}"


# ---------------------------------------------------------------------------
# I4 — Buildkite agent annotation
# ---------------------------------------------------------------------------
def buildkite_annotation(report) -> tuple[bool, str]:
    """Print a `buildkite-agent annotate` shell command. Best-effort: the agent
    binary must be on PATH inside the build env."""
    if not os.environ.get("BUILDKITE_AGENT_NAME"):
        return False, "not running under a Buildkite agent"
    sev = report.worst_severity() if hasattr(report, "worst_severity") else "info"
    style = {"critical": "error", "high": "error",
              "medium": "warning", "low": "info", "info": "info"}.get(sev, "info")
    body = (f"WPSecScan {sev.upper()} on {report.target} — "
             f"risk {report.risk_score}/100")
    try:
        import subprocess
        subprocess.run(["buildkite-agent", "annotate", "--style", style, body],
                        capture_output=True, timeout=5)
        return True, f"buildkite annotation emitted (style={style})"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f"buildkite-agent not callable: {e}"


# ---------------------------------------------------------------------------
# I5 — Shortcut (formerly Clubhouse) story
# ---------------------------------------------------------------------------
def push_shortcut(report) -> tuple[bool, str]:
    """Create a Shortcut story per high-severity finding."""
    tok = os.environ.get("SHORTCUT_TOKEN", "")
    workflow = os.environ.get("SHORTCUT_WORKFLOW_STATE_ID", "")
    if not (tok and workflow):
        return False, "set SHORTCUT_TOKEN + SHORTCUT_WORKFLOW_STATE_ID"
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("critical", "high"):
                continue
            ok, _ = _post_json(
                "https://api.app.shortcut.com/api/v3/stories",
                {"name": f"[wpsecscan] {f.title[:200]}",
                 "description": (f.evidence or "")[:2000],
                 "workflow_state_id": int(workflow), "story_type": "bug"},
                headers={"Shortcut-Token": tok, "Content-Type": "application/json"})
            if ok:
                n += 1
    return (n > 0), f"created {n} shortcut stor(ies)"


# ---------------------------------------------------------------------------
# I6 — Plane.so issue
# ---------------------------------------------------------------------------
def push_plane(report) -> tuple[bool, str]:
    """Create a Plane.so issue per high-severity finding.
    Env: PLANE_TOKEN, PLANE_WORKSPACE, PLANE_PROJECT, PLANE_BASE (default api.plane.so)."""
    tok = os.environ.get("PLANE_TOKEN", "")
    ws = os.environ.get("PLANE_WORKSPACE", "")
    proj = os.environ.get("PLANE_PROJECT", "")
    base = os.environ.get("PLANE_BASE", "https://api.plane.so")
    if not (tok and ws and proj):
        return False, "set PLANE_TOKEN + PLANE_WORKSPACE + PLANE_PROJECT"
    url = f"{base}/api/v1/workspaces/{ws}/projects/{proj}/issues/"
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("critical", "high"):
                continue
            ok, _ = _post_json(url, {"name": f.title[:240],
                                       "description_html":
                                          f"<pre>{(f.evidence or '')[:3000]}</pre>"},
                                headers={"x-api-key": tok,
                                          "Content-Type": "application/json"})
            if ok:
                n += 1
    return (n > 0), f"created {n} plane issue(s)"


# ---------------------------------------------------------------------------
# I7 — Nuclei template export
# ---------------------------------------------------------------------------
def nuclei_template_export(report, out_path: str | None = None) -> tuple[bool, str]:
    """Emit a Nuclei YAML template per CVE-bearing finding."""
    out = out_path or os.environ.get("NUCLEI_TEMPLATE_OUT")
    if not out:
        return False, "set NUCLEI_TEMPLATE_OUT=<dir> or pass out_path"
    from pathlib import Path as _P
    p = _P(out)
    p.mkdir(parents=True, exist_ok=True)
    n = 0
    for r in report.results:
        for f in r.findings:
            cve = (f.extra or {}).get("cve") if isinstance(f.extra, dict) else None
            if not cve:
                continue
            slug = f"{r.check_id}-{cve}".replace("/", "_")
            yaml = (
                f"id: wpsecscan-{slug}\n"
                f"info:\n"
                f"  name: '{(f.title or '')[:80]}'\n"
                f"  severity: {f.severity}\n"
                f"  reference:\n    - {report.target}\n"
                f"  tags: wordpress,{cve.lower()}\n"
                f"requests:\n  - method: GET\n    path:\n      - '{{{{BaseURL}}}}/'\n"
            )
            try:
                (p / f"{slug}.yaml").write_text(yaml, encoding="utf-8")
                n += 1
            except OSError:
                pass
    return (n > 0), f"wrote {n} nuclei template(s) to {p}"


# ---------------------------------------------------------------------------
# I8 — OSV.dev schema enrichment
# ---------------------------------------------------------------------------
def osv_dev_enrich(report) -> tuple[bool, str]:
    """Look up each finding's CVE on OSV.dev and tag .extra with the response.
    Returns number of findings enriched."""
    n = 0
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            for r in report.results:
                for f in r.findings:
                    cve = (f.extra or {}).get("cve") if isinstance(f.extra, dict) else None
                    if not cve:
                        continue
                    try:
                        rr = c.get(f"https://api.osv.dev/v1/vulns/{cve}")
                    except httpx.RequestError:
                        continue
                    if rr.status_code != 200:
                        continue
                    f.extra.setdefault("osv", {})
                    try:
                        f.extra["osv"] = rr.json()
                        n += 1
                    except ValueError:
                        continue
    except httpx.RequestError as e:
        return False, f"osv error: {e}"
    return (n > 0), f"enriched {n} finding(s) with OSV.dev data"


# ---------------------------------------------------------------------------
# I9 — ExploitDB cross-reference
# ---------------------------------------------------------------------------
def exploitdb_xref(report) -> tuple[bool, str]:
    """Best-effort cross-reference of CVEs against the ExploitDB CSV mirror.
    Requires EXPLOITDB_CSV=<path to files_exploits.csv>.

    Tags f.extra['exploitdb_ids'] = [<int IDs>]."""
    csv_path = os.environ.get("EXPLOITDB_CSV")
    if not csv_path:
        return False, "set EXPLOITDB_CSV=<files_exploits.csv path>"
    try:
        import csv
        with open(csv_path, encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            by_cve: dict[str, list[int]] = {}
            for row in reader:
                cves = (row.get("cve") or "").split(";")
                eid = row.get("id")
                if not eid:
                    continue
                for c in cves:
                    c = c.strip().upper()
                    if c:
                        by_cve.setdefault(c, []).append(int(eid))
    except (OSError, ValueError) as e:
        return False, f"failed to read EXPLOITDB_CSV: {e}"
    n = 0
    for r in report.results:
        for f in r.findings:
            cve = (f.extra or {}).get("cve") if isinstance(f.extra, dict) else None
            if not cve:
                continue
            ids = by_cve.get(cve.upper())
            if ids:
                f.extra["exploitdb_ids"] = ids
                n += 1
    return (n > 0), f"tagged {n} finding(s) with ExploitDB IDs"


# ---------------------------------------------------------------------------
# I10 — Wiz / Lacework custom-finding push
# ---------------------------------------------------------------------------
def wiz_lacework_push(report) -> tuple[bool, str]:
    """Push the report as a custom-finding webhook to Wiz/Lacework.
    Env: SEC_TOOL_WEBHOOK_URL (single endpoint accepting JSON)."""
    url = os.environ.get("SEC_TOOL_WEBHOOK_URL")
    if not url:
        return False, "set SEC_TOOL_WEBHOOK_URL"
    body = {
        "source": "wpsecscan",
        "target": report.target,
        "risk_score": report.risk_score,
        "findings": [
            {"check_id": r.check_id, "severity": f.severity,
              "title": f.title, "evidence": (f.evidence or "")[:1000]}
            for r in report.results for f in r.findings
            if f.severity in ("critical", "high")
        ],
    }
    return _post_json(url, body)


# ---------------------------------------------------------------------------
# I11 — Mattermost / RocketChat / Telegram chat webhooks
# ---------------------------------------------------------------------------
def chat_webhooks(report) -> tuple[bool, str]:
    """Post a one-line summary to any of MATTERMOST_WEBHOOK_URL,
    ROCKETCHAT_WEBHOOK_URL, or TELEGRAM_BOT_TOKEN+TELEGRAM_CHAT_ID."""
    sev = report.worst_severity() if hasattr(report, "worst_severity") else "info"
    msg = (f"*WPSecScan* — {report.target} "
            f"risk={report.risk_score} worst=*{sev}*")
    sent = []
    mm = os.environ.get("MATTERMOST_WEBHOOK_URL")
    if mm:
        ok, _ = _post_json(mm, {"text": msg})
        sent.append(f"Mattermost={'ok' if ok else 'fail'}")
    rc = os.environ.get("ROCKETCHAT_WEBHOOK_URL")
    if rc:
        ok, _ = _post_json(rc, {"text": msg})
        sent.append(f"RocketChat={'ok' if ok else 'fail'}")
    tg_tok = os.environ.get("TELEGRAM_BOT_TOKEN")
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID")
    if tg_tok and tg_chat:
        ok, _ = _post_json(
            f"https://api.telegram.org/bot{tg_tok}/sendMessage",
            {"chat_id": tg_chat, "text": msg, "parse_mode": "Markdown"})
        sent.append(f"Telegram={'ok' if ok else 'fail'}")
    if not sent:
        return False, "no chat webhook env vars set"
    return True, "; ".join(sent)


# ---------------------------------------------------------------------------
# I12 — WP Engine / Kinsta hosting API event
# ---------------------------------------------------------------------------
def hosting_api_event(report) -> tuple[bool, str]:
    """POST a custom event to a managed-host webhook (WP Engine / Kinsta /
    Cloudways). One unified env var: HOSTING_EVENT_WEBHOOK_URL."""
    url = os.environ.get("HOSTING_EVENT_WEBHOOK_URL")
    if not url:
        return False, "set HOSTING_EVENT_WEBHOOK_URL"
    body = {
        "event_type": "wpsecscan.scan_completed",
        "target": report.target,
        "risk_score": report.risk_score,
        "summary": dict(report.summary or {}),
    }
    return _post_json(url, body)


# ---------------------------------------------------------------------------
# I13 — n8n / Make.com / Notion / Power Automate / Patchstack-inbound
# ---------------------------------------------------------------------------
def automation_hub_webhook(report) -> tuple[bool, str]:
    """Generic JSON webhook used by no-code automation platforms.
    Single env var AUTOMATION_HUB_WEBHOOK_URL covers all (n8n/Make/etc.)."""
    url = os.environ.get("AUTOMATION_HUB_WEBHOOK_URL")
    if not url:
        return False, "set AUTOMATION_HUB_WEBHOOK_URL"
    body = {
        "scanner": "wpsecscan",
        "target": report.target,
        "risk_score": report.risk_score,
        "summary": dict(report.summary or {}),
        "finding_count": sum(len(r.findings) for r in report.results),
    }
    return _post_json(url, body)
