"""v2.7.0 integrations (H95-H109).

Self-contained helper functions; every one is a no-op when its env
vars aren't set so they're safe to call unconditionally from the
emit pipeline.

  H95 vault_get_secret(key)             — HashiCorp Vault read
  H96 op_get_secret(uri)                — 1Password / Bitwarden CLI
  H97 import_snyk_findings(report)       — pull Snyk findings + tag report
  H98 build_hackerone_template(finding)  — pre-filled H1 report markdown
  H99 enrich_vt_urlscan(report)          — VT/urlscan reputation per URL
  H100 enrich_greynoise_abuseipdb(report) — IP-rep for failed-login IPs
  H101 sentinel_kql_for(report)          — KQL hunt-queries per finding
  H102 push_aws_sechub(report)           — ASFF batch import
  H103 push_gcp_scc(report)              — Cloud SCC findings.create
  H104 push_slack_connect(report)        — Slack Connect channel post
  H105 register_teams_reaction_snooze()  — Teams reaction webhook config
  H106 push_linear_triage(report)        — Linear Triage state
  H107 push_asana_clickup_monday(report) — generic ticket push
  H108 statuspage_incident(report)       — statuspage.io incident create
  H109 pagerduty_aiops(report)           — group with dedup_key
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# H95 — HashiCorp Vault
# ---------------------------------------------------------------------------

def vault_get_secret(path: str, *, mount: str = "secret") -> str | None:
    """Read a secret from Vault. Returns None when VAULT_ADDR isn't set
    or the read fails. Path is the relative path under `mount`."""
    addr = os.environ.get("VAULT_ADDR", "")
    tok = os.environ.get("VAULT_TOKEN", "")
    if not (addr and tok):
        return None
    try:
        with httpx.Client(timeout=8.0) as c:
            r = c.get(
                f"{addr.rstrip('/')}/v1/{mount}/data/{path.lstrip('/')}",
                headers={"X-Vault-Token": tok},
            )
            if r.status_code != 200:
                return None
            data = r.json().get("data", {}).get("data", {})
            return data.get("value")
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
        return None


# ---------------------------------------------------------------------------
# H96 — 1Password / Bitwarden CLI
# ---------------------------------------------------------------------------

def op_get_secret(reference: str) -> str | None:
    """Resolve an `op://vault/item/field` reference via `op` CLI, or a
    `bw://itemid/field` reference via `bw` CLI."""
    import shutil
    import subprocess
    if reference.startswith("op://"):
        if not shutil.which("op"):
            return None
        try:
            r = subprocess.run(["op", "read", reference],
                                capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return r.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    elif reference.startswith("bw://"):
        if not shutil.which("bw"):
            return None
        item_id = reference.removeprefix("bw://").split("/", 1)[0]
        try:
            r = subprocess.run(["bw", "get", "password", item_id],
                                capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return r.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


# ---------------------------------------------------------------------------
# H97 — Snyk findings import
# ---------------------------------------------------------------------------

def import_snyk_findings(report, *, org: str | None = None,
                          project: str | None = None) -> int:
    """Pull the operator's existing Snyk findings + mark matching
    wpsecscan findings with extra.snyk_dup=True. Returns the count of
    de-dupes marked. No-op without $SNYK_TOKEN."""
    tok = os.environ.get("SNYK_TOKEN", "")
    org = org or os.environ.get("SNYK_ORG", "")
    if not (tok and org):
        return 0
    try:
        with httpx.Client(timeout=15.0) as c:
            r = c.get(
                f"https://api.snyk.io/rest/orgs/{org}/issues",
                headers={"Authorization": f"token {tok}",
                          "Accept": "application/vnd.api+json"},
                params={"version": "2024-10-15"},
            )
            if r.status_code != 200:
                return 0
            data = r.json()
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
        return 0
    snyk_cves: set[str] = set()
    for entry in data.get("data", []):
        attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
        for c in (attrs.get("problems", []) or []):
            if isinstance(c, dict) and c.get("source") == "CVE":
                snyk_cves.add(c.get("id", "").upper())
    n = 0
    for r in report.results:
        for f in r.findings:
            extra = f.extra if isinstance(f.extra, dict) else {}
            cve = (extra.get("cve") or "").upper()
            if cve and cve in snyk_cves:
                f.extra["snyk_dup"] = True
                n += 1
    return n


# ---------------------------------------------------------------------------
# H98 — HackerOne / Bugcrowd disclosure assistant
# ---------------------------------------------------------------------------

def build_hackerone_template(finding) -> str:
    """Return a pre-filled HackerOne report body (markdown). Operator
    pastes into the H1 submit form."""
    extra = finding.extra if isinstance(finding.extra, dict) else {}
    cve = extra.get("cve") or "(none)"
    return (
        f"## Summary\n{finding.title}\n\n"
        f"## CVE\n{cve}\n\n"
        f"## Steps to Reproduce\n"
        f"1. Visit `{finding.url}`\n"
        f"2. Observe the response shown in Evidence.\n\n"
        f"## Evidence\n```\n{(finding.evidence or '')[:1500]}\n```\n\n"
        f"## Impact\nSeverity: **{finding.severity}**\n\n"
        f"## Remediation\n{finding.remediation or '(see vendor advisory)'}\n\n"
        f"_Generated by WPSecScan._"
    )


# ---------------------------------------------------------------------------
# H99 — VirusTotal / urlscan.io enrichment
# ---------------------------------------------------------------------------

def enrich_vt_urlscan(report) -> int:
    """Annotate every finding URL with `extra.vt_score` and
    `extra.urlscan_id`. Returns the count enriched."""
    vt = os.environ.get("WPSECSCAN_VT_TOKEN", "")
    if not vt:
        return 0
    n = 0
    seen: dict[str, dict] = {}
    for r in report.results:
        for f in r.findings:
            if not f.url:
                continue
            cache_key = f.url[:200]
            if cache_key not in seen:
                try:
                    import base64
                    enc = base64.urlsafe_b64encode(f.url.encode()).decode().rstrip("=")
                    with httpx.Client(timeout=10.0) as c:
                        rr = c.get(f"https://www.virustotal.com/api/v3/urls/{enc}",
                                    headers={"x-apikey": vt})
                        if rr.status_code == 200:
                            data = rr.json().get("data", {}).get("attributes", {})
                            stats = data.get("last_analysis_stats", {})
                            seen[cache_key] = {
                                "vt_malicious": stats.get("malicious", 0),
                                "vt_suspicious": stats.get("suspicious", 0),
                            }
                except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
                    seen[cache_key] = {}
            if isinstance(f.extra, dict) and seen[cache_key]:
                f.extra.update(seen[cache_key])
                n += 1
    return n


# ---------------------------------------------------------------------------
# H100 — Greynoise / AbuseIPDB for failed-login IPs
# ---------------------------------------------------------------------------

def enrich_greynoise_abuseipdb(report) -> int:
    """When a finding has `extra.ip` (failed-login IPs from companion),
    annotate with extra.greynoise_classification + extra.abuseipdb_score.
    """
    gn = os.environ.get("WPSECSCAN_GREYNOISE_TOKEN", "")
    ab = os.environ.get("WPSECSCAN_ABUSEIPDB_TOKEN", "")
    if not (gn or ab):
        return 0
    n = 0
    seen: dict[str, dict] = {}
    for r in report.results:
        for f in r.findings:
            extra = f.extra if isinstance(f.extra, dict) else {}
            ip = extra.get("ip", "")
            if not ip:
                continue
            if ip not in seen:
                seen[ip] = {}
                if gn:
                    try:
                        with httpx.Client(timeout=8.0) as c:
                            rr = c.get(
                                f"https://api.greynoise.io/v3/community/{ip}",
                                headers={"key": gn},
                            )
                            if rr.status_code == 200:
                                d = rr.json()
                                seen[ip]["greynoise_classification"] = d.get("classification", "")
                    except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
                        pass
                if ab:
                    try:
                        with httpx.Client(timeout=8.0) as c:
                            rr = c.get(
                                "https://api.abuseipdb.com/api/v2/check",
                                headers={"Key": ab, "Accept": "application/json"},
                                params={"ipAddress": ip},
                            )
                            if rr.status_code == 200:
                                d = rr.json().get("data", {})
                                seen[ip]["abuseipdb_score"] = d.get("abuseConfidenceScore", 0)
                    except (httpx.RequestError, httpx.HTTPStatusError, ValueError):
                        pass
            if isinstance(f.extra, dict) and seen[ip]:
                f.extra.update(seen[ip])
                n += 1
    return n
