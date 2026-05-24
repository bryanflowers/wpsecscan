"""Round-62 integrations bundle (#D51-D60).

#D51 burp_project_xml       — export WPSecScan report as a Burp Suite project
#D52 zap_findings_import    — import OWASP ZAP scan JSON into WPSecScan report
#D53 nuclei_template_import — pull projectdiscovery/nuclei-templates from GitHub
#D54 wordfence_cloud_sync   — read your Wordfence findings into a WPSecScan-style list
#D55 sucuri_sitecheck       — call Sucuri's free SiteCheck API
#D56 patchstack_writeback   — submit your CVE finding to Patchstack MVDP
#D57 wpscan_writeback       — submit your CVE finding to WPScan
#D58 wp_host_apis           — WP Engine / Kinsta / WP.com host API summaries
#D59 n8n_recipe_templates   — bundled n8n workflow JSONs
#D60 vscode_extension_stub  — see editor/vscode/ (already exists)
"""
from __future__ import annotations

import html
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError


def _post_json(url: str, body: dict, headers: dict | None = None,
                timeout: float = 15.0) -> dict | None:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                  "User-Agent": "WPSecScan/integrations.round62",
                  **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def _get_json(url: str, headers: dict | None = None,
               timeout: float = 15.0) -> dict | None:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/integrations.round62",
                                                  **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def _findings_iter(rep):
    d = rep.to_dict() if hasattr(rep, "to_dict") else (rep or {})
    for r in d.get("results", []) or []:
        cid = r.get("check_id", "?")
        for f in r.get("findings", []) or []:
            yield cid, f


# ---- #D51 Burp project XML export ----

def burp_project_xml(report: Any) -> str:
    """Build a Burp Suite XML project file (.burp) listing every finding's
    URL + evidence as a request/response pair. Burp can import this via
    File → Import → New State."""
    d = report.to_dict() if hasattr(report, "to_dict") else (report or {})
    target = d.get("target", "")
    items: list[str] = []
    for cid, f in _findings_iter(d):
        url = html.escape(f.get("url") or target)
        title = html.escape(f.get("title") or "")
        evidence = html.escape((f.get("evidence") or "")[:2000])
        items.append(
            f"  <item>\n"
            f"    <time>{int(time.time())}</time>\n"
            f"    <url><![CDATA[{url}]]></url>\n"
            f"    <host>{html.escape(target)}</host>\n"
            f"    <method>GET</method>\n"
            f"    <comment><![CDATA[wpsecscan {cid}: {title}]]></comment>\n"
            f"    <response base64=\"false\"><![CDATA[{evidence}]]></response>\n"
            f"  </item>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE items SYSTEM "https://portswigger.net/burp/schema/items.dtd">\n'
        '<items burpVersion="2024.1" exportTime="' + str(int(time.time())) + '">\n'
        + "\n".join(items) + "\n</items>\n"
    )


# ---- #D52 ZAP findings import ----

def zap_findings_import(zap_json_path: str) -> list[dict]:
    """Read OWASP ZAP JSON output (`zap-cli report -o report.json`) and
    return a list of WPSecScan-finding-shaped dicts. Caller can merge."""
    p = Path(zap_json_path)
    if not p.exists() or p.is_symlink():
        return []
    try:
        z = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[dict] = []
    sev_map = {"3": "high", "2": "medium", "1": "low", "0": "info",
                "informational": "info", "low": "low", "medium": "medium",
                "high": "high", "critical": "critical"}
    for site in z.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            risk = str(alert.get("riskcode", "")).lower() or str(alert.get("risk", "")).lower()
            sev = sev_map.get(risk, "info")
            instances = alert.get("instances", []) or [{}]
            for inst in instances:
                out.append({
                    "severity":   sev,
                    "title":      f"[ZAP] {alert.get('alert') or alert.get('name', '?')}",
                    "url":        inst.get("uri", site.get("@host", "")),
                    "evidence":   (alert.get("desc", "") + "\n\n" + inst.get("evidence", ""))[:2000],
                    "remediation": (alert.get("solution", "") or "")[:2000],
                    "extra":      {"zap_pluginid": alert.get("pluginid", ""),
                                     "zap_cweid": alert.get("cweid", "")},
                })
    return out


# ---- #D53 Nuclei template auto-import ----

def nuclei_template_pull(out_dir: str | None = None, *,
                          template_dir: str = "http",
                          max_files: int = 200) -> dict:
    """Pull a slice of projectdiscovery/nuclei-templates from GitHub.
    Returns {downloaded, skipped, errors}.

    out_dir defaults to ~/.wpsecscan/nuclei-templates/.
    Caps at `max_files` to avoid pulling all 8000+ in one shot.
    """
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return {"downloaded": 0, "skipped": 0, "errors": "WPSECSCAN_NO_NETWORK"}
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    target_dir = Path(out_dir or (home / "nuclei-templates"))
    target_dir.mkdir(parents=True, exist_ok=True)

    # GitHub API tree listing — anonymous, rate-limited (60/hour)
    tree = _get_json(
        f"https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1",
        timeout=30.0,
    ) or {}
    items = tree.get("tree", []) or []
    yaml_paths = [it["path"] for it in items
                   if isinstance(it, dict) and it.get("type") == "blob"
                   and it.get("path", "").startswith(template_dir + "/")
                   and it.get("path", "").endswith(".yaml")][:max_files]

    downloaded = 0
    errors = 0
    for p in yaml_paths:
        url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{urllib.parse.quote(p)}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/nuclei-import"})
            with urllib.request.urlopen(req, timeout=15) as r:
                if r.status != 200:
                    errors += 1
                    continue
                content = r.read()
        except (HTTPError, URLError, OSError):
            errors += 1
            continue
        dest = target_dir / Path(p).name
        if dest.is_symlink():
            try:
                dest.unlink()
            except OSError:
                continue
        try:
            dest.write_bytes(content)
            downloaded += 1
        except OSError:
            errors += 1
    return {"downloaded": downloaded, "errors": errors, "total_listed": len(yaml_paths),
             "dir": str(target_dir)}


# ---- #D54 Wordfence Cloud sync ----

def wordfence_cloud_sync(api_key: str | None = None) -> list[dict]:
    """Read your Wordfence Central findings via their public API and
    return WPSecScan-finding-shaped dicts. API key required."""
    api_key = api_key or os.environ.get("WORDFENCE_API_KEY", "")
    if not api_key:
        return []
    # Wordfence Central API is paid + per-account; documented at
    # https://www.wordfence.com/help/wordfence-central/. The endpoint
    # below is the public-facing /scan-results path; replace with your
    # actual installation.
    data = _get_json(
        "https://api.wordfence.com/v1/scan-results",
        headers={"Authorization": f"Bearer {api_key}"},
    ) or {}
    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "info": "info"}
    out = []
    for r in data.get("results", []) or []:
        out.append({
            "severity":   sev_map.get((r.get("severity") or "info").lower(), "info"),
            "title":      f"[Wordfence] {r.get('title') or r.get('name', '?')}",
            "url":        r.get("url", ""),
            "evidence":   (r.get("description") or "")[:2000],
            "remediation": (r.get("remediation") or "")[:2000],
            "extra":      {"wordfence_id": r.get("id")},
        })
    return out


# ---- #D55 Sucuri SiteCheck ----

def sucuri_sitecheck(target_url: str) -> dict:
    """Call Sucuri's free SiteCheck API. Returns the raw JSON or {}."""
    return _get_json(
        f"https://sitecheck.sucuri.net/api/v3/?scan={urllib.parse.quote(target_url)}",
        timeout=30.0,
    ) or {}


# ---- #D56 Patchstack write-back ----

def patchstack_submit(finding: dict, *, vendor: str = "",
                       api_key: str | None = None) -> dict:
    """Submit a finding to Patchstack's MVDP via their JSON API."""
    api_key = api_key or os.environ.get("PATCHSTACK_API_KEY", "")
    if not api_key:
        return {"ok": False, "hint": "PATCHSTACK_API_KEY env var required"}
    payload = {
        "vendor":      vendor or "Unknown",
        "title":       (finding.get("title") or "")[:255],
        "severity":    finding.get("severity"),
        "url":         finding.get("url"),
        "description": (finding.get("evidence") or "")[:5000],
        "remediation": (finding.get("remediation") or "")[:5000],
        "discovered_by": "WPSecScan",
    }
    return _post_json(
        "https://patchstack.com/api/v2/mvdp/submit",
        payload,
        headers={"Authorization": f"Bearer {api_key}"},
    ) or {"ok": False}


# ---- #D57 WPScan write-back ----

def wpscan_submit(finding: dict, *, slug: str = "",
                   api_token: str | None = None) -> dict:
    """Submit a vulnerability to WPScan's vulnerability database via their
    /v3/submission API (token-gated)."""
    api_token = api_token or os.environ.get("WPSCAN_API_TOKEN", "")
    if not api_token:
        return {"ok": False, "hint": "WPSCAN_API_TOKEN env var required"}
    payload = {
        "slug":        slug or "unknown",
        "title":       finding.get("title"),
        "severity":    finding.get("severity"),
        "url":         finding.get("url"),
        "description": (finding.get("evidence") or "")[:5000],
        "remediation": (finding.get("remediation") or "")[:5000],
    }
    return _post_json(
        "https://wpscan.com/api/v3/submissions",
        payload,
        headers={"Authorization": f"Token token={api_token}"},
    ) or {"ok": False}


# ---- #D58 WP host APIs ----

def wpengine_site_state(install_id: str, *, api_token: str | None = None) -> dict:
    """Fetch installation state from WP Engine's API."""
    api_token = api_token or os.environ.get("WPENGINE_API_TOKEN", "")
    if not api_token:
        return {"error": "WPENGINE_API_TOKEN env var required"}
    return _get_json(
        f"https://api.wpengineapi.com/v1/installs/{install_id}",
        headers={"Authorization": f"Bearer {api_token}"},
    ) or {}


def kinsta_site_state(site_id: str, *, api_token: str | None = None) -> dict:
    api_token = api_token or os.environ.get("KINSTA_API_TOKEN", "")
    if not api_token:
        return {"error": "KINSTA_API_TOKEN env var required"}
    return _get_json(
        f"https://api.kinsta.com/v2/sites/{site_id}",
        headers={"Authorization": f"Bearer {api_token}"},
    ) or {}


def wpcom_site_state(site_id_or_domain: str, *, api_token: str | None = None) -> dict:
    api_token = api_token or os.environ.get("WPCOM_API_TOKEN", "")
    if not api_token:
        return {"error": "WPCOM_API_TOKEN env var required"}
    return _get_json(
        f"https://public-api.wordpress.com/rest/v1.1/sites/{urllib.parse.quote(site_id_or_domain)}",
        headers={"Authorization": f"Bearer {api_token}"},
    ) or {}


# ---- #D59 n8n recipe templates ----

def n8n_recipe(name: str = "weekly-scan") -> dict:
    """Return an n8n workflow JSON for a common WPSecScan automation.

    Valid names: "weekly-scan" — run wpsecscan, POST report to Slack.
                  "cve-alert"    — webhook subscriber that forwards to email.
                  "ci-gate"      — fail CI if scan > threshold.
    """
    common_target = "https://yoursite.example"
    if name == "weekly-scan":
        return {
            "name": "WPSecScan weekly + Slack digest",
            "nodes": [
                {"name": "Cron", "type": "n8n-nodes-base.cron", "position": [200, 200],
                  "parameters": {"triggerTimes": {"item": [{"mode": "everyWeek",
                                                                "weekday": 1, "hour": 3}]}}},
                {"name": "Run wpsecscan", "type": "n8n-nodes-base.executeCommand",
                  "position": [500, 200],
                  "parameters": {"command": f"wpsecscan --target {common_target} --json -"}},
                {"name": "Slack post", "type": "n8n-nodes-base.slack", "position": [800, 200],
                  "parameters": {"channel": "#sec-alerts", "text": "={{ $json.summary }}"}},
            ],
            "connections": {"Cron": {"main": [[{"node": "Run wpsecscan", "type": "main", "index": 0}]]},
                              "Run wpsecscan": {"main": [[{"node": "Slack post", "type": "main", "index": 0}]]}},
        }
    if name == "cve-alert":
        return {
            "name": "WPSecScan CVE alert → email",
            "nodes": [
                {"name": "Webhook", "type": "n8n-nodes-base.webhook", "position": [200, 200],
                  "parameters": {"path": "wpsecscan-cve", "responseMode": "onReceived"}},
                {"name": "Email", "type": "n8n-nodes-base.emailSend", "position": [500, 200],
                  "parameters": {"toEmail": "ops@yourorg.example",
                                   "subject": "WPSecScan CVE alert — {{ $json.site_url }}",
                                   "text": "{{ $json.title }}\n\n{{ $json.cve }}"}},
            ],
            "connections": {"Webhook": {"main": [[{"node": "Email", "type": "main", "index": 0}]]}},
        }
    if name == "ci-gate":
        return {
            "name": "WPSecScan CI gate (GitHub status)",
            "nodes": [
                {"name": "Webhook", "type": "n8n-nodes-base.webhook", "position": [200, 200],
                  "parameters": {"path": "wpsecscan-ci"}},
                {"name": "GitHub status", "type": "n8n-nodes-base.github", "position": [500, 200],
                  "parameters": {"operation": "createStatus",
                                   "state": "={{ $json.summary.critical > 0 ? 'failure' : 'success' }}"}},
            ],
            "connections": {"Webhook": {"main": [[{"node": "GitHub status", "type": "main", "index": 0}]]}},
        }
    return {"error": "unknown recipe name"}
