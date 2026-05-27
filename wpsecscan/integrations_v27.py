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


# ---------------------------------------------------------------------------
# H101 — Microsoft Sentinel KQL hunt queries
# ---------------------------------------------------------------------------

_KQL_TEMPLATES = {
    "xmlrpc_deep":            "OfficeActivity | where Url contains \"/xmlrpc.php\"",
    "login_throttle":         "SigninLogs | where TargetResource == \"{target}\" | summarize fails=countif(ResultType != 0) by IPAddress | where fails > 20",
    "core_cves":              "SecurityEvent | where ProcessCommandLine contains \"{check_id}\"",
    "wp_cli_http_exposure":   "W3CIISLog | where csUriStem contains \"wp-cli\"",
    "mcp_endpoint_exposure":  "W3CIISLog | where csUriStem contains \"/mcp\"",
}


def sentinel_kql_for(report) -> str:
    """Return a single KQL document with one stanza per fired check."""
    seen = {r.check_id for r in report.results if r.findings}
    lines = [f"// Sentinel hunt queries auto-generated by WPSecScan",
              f"// Target: {report.target}",
              f"// Scanned: {report.scanned_at}", ""]
    for cid in sorted(seen):
        tpl = _KQL_TEMPLATES.get(cid)
        if not tpl:
            continue
        lines.append(f"// {cid}")
        lines.append(tpl.replace("{target}", report.target).replace("{check_id}", cid))
        lines.append("")
    return "\n".join(lines) or "// (no fired check has a Sentinel KQL template — extend _KQL_TEMPLATES)"


# ---------------------------------------------------------------------------
# H102 — AWS Security Hub (ASFF batch import)
# ---------------------------------------------------------------------------

def push_aws_sechub(report) -> tuple[bool, str]:
    """Push findings to AWS Security Hub as ASFF. Requires AWS creds
    in env (AWS_ACCESS_KEY_ID etc.). Uses boto3 if installed."""
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError:
        return False, "boto3 not installed; pip install boto3"
    region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
    if not region:
        return False, "set AWS_DEFAULT_REGION / AWS_REGION"
    account = os.environ.get("AWS_ACCOUNT_ID")
    if not account:
        return False, "set AWS_ACCOUNT_ID (sec-hub findings need it in ProductArn)"
    findings_asff = []
    from .. import __version__ as _v  # type: ignore[no-redef]
    for r in report.results:
        for i, f in enumerate(r.findings):
            findings_asff.append({
                "SchemaVersion": "2018-10-08",
                "Id": f"wpsecscan/{r.check_id}/{i}/{report.scanned_at}",
                "ProductArn": f"arn:aws:securityhub:{region}:{account}:product/{account}/default",
                "GeneratorId": f"wpsecscan/{r.check_id}",
                "AwsAccountId": account,
                "Types": [f"Software and Configuration Checks/{r.check_id}"],
                "CreatedAt": report.scanned_at,
                "UpdatedAt": report.scanned_at,
                "Severity": {"Label": f.severity.upper()},
                "Title": f.title[:256],
                "Description": (f.evidence or "")[:1024],
                "Resources": [{"Type": "Other", "Id": f.url or report.target,
                                "Partition": "aws", "Region": region}],
            })
    try:
        sec = boto3.client("securityhub", region_name=region)
        # ASFF caps at 100 findings per BatchImportFindings call
        sent = 0
        for i in range(0, len(findings_asff), 100):
            chunk = findings_asff[i:i + 100]
            res = sec.batch_import_findings(Findings=chunk)
            sent += int(res.get("SuccessCount", 0))
        return True, f"AWS Sec Hub: {sent}/{len(findings_asff)} findings imported"
    except Exception as e:  # noqa: BLE001
        return False, f"sec-hub error: {e}"


# ---------------------------------------------------------------------------
# H103 — GCP Security Command Center
# ---------------------------------------------------------------------------

def push_gcp_scc(report) -> tuple[bool, str]:
    """Push findings to GCP SCC via the REST API. Requires
    GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account JSON +
    GCP_ORG_ID + GCP_SOURCE_ID."""
    org = os.environ.get("GCP_ORG_ID", "")
    source = os.environ.get("GCP_SOURCE_ID", "")
    creds_file = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not (org and source and creds_file):
        return False, "GCP_ORG_ID / GCP_SOURCE_ID / GOOGLE_APPLICATION_CREDENTIALS required"
    try:
        from google.cloud import securitycenter  # type: ignore[import-not-found]
        client = securitycenter.SecurityCenterClient()
    except ImportError:
        return False, "google-cloud-securitycenter not installed"
    source_path = f"organizations/{org}/sources/{source}"
    n = 0
    for r in report.results:
        for i, f in enumerate(r.findings):
            fid = f"wpsecscan-{r.check_id}-{i}-{int.from_bytes((f.title or '').encode()[:8], 'little')}"
            try:
                client.create_finding(
                    request={
                        "parent": source_path,
                        "finding_id": fid,
                        "finding": {
                            "state": "ACTIVE",
                            "category": r.check_id,
                            "external_uri": f.url or report.target,
                            "source_properties": {
                                "title": f.title,
                                "evidence": (f.evidence or "")[:1024],
                            },
                            "severity": f.severity.upper(),
                        },
                    },
                )
                n += 1
            except Exception:  # noqa: BLE001
                continue
    return True, f"GCP SCC: {n} findings pushed"


# ---------------------------------------------------------------------------
# H104 — Slack Connect channel post
# ---------------------------------------------------------------------------

def push_slack_connect(report) -> tuple[bool, str]:
    """Post to a Slack Connect channel (different from internal Slack
    via the existing webhook). Uses WPSECSCAN_SLACK_CONNECT_WEBHOOK so
    the operator can have a separate destination for client-shared
    findings vs internal ops alerts."""
    url = os.environ.get("WPSECSCAN_SLACK_CONNECT_WEBHOOK", "")
    if not url:
        return False, "set WPSECSCAN_SLACK_CONNECT_WEBHOOK"
    s = report.summary
    payload = {
        "text": (
            f"WPSecScan results for *{report.target}*: "
            f"score {report.risk_score}/100 — "
            f"{s.get('critical', 0)} critical / {s.get('high', 0)} high / "
            f"{s.get('medium', 0)} medium / {s.get('low', 0)} low / "
            f"{s.get('info', 0)} info."
        )
    }
    try:
        with httpx.Client(timeout=10.0) as c:
            r = c.post(url, json=payload)
            if r.status_code in (200, 204):
                return True, "slack-connect posted"
            return False, f"slack-connect: HTTP {r.status_code}"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return False, f"slack-connect error: {e}"


# ---------------------------------------------------------------------------
# H105 — Teams reaction-as-snooze configuration
# ---------------------------------------------------------------------------

def register_teams_reaction_snooze() -> str:
    """Document the operator's reaction-snooze flow. Returns markdown
    text the operator pastes into their Teams admin notes. The actual
    reaction listener is a Teams app-side bot the operator builds;
    we just supply the contract."""
    return (
        "## WPSecScan + Teams reaction-as-snooze\n\n"
        "1. Create a Teams bot subscribed to the reaction-added event.\n"
        "2. On 👍 reaction, POST `{\"action\":\"snooze\",\"finding_key\":\""
        "<from-message>\"}` to your WPSecScan host's "
        "`/api/snooze` endpoint (`wpsecscan slack-app` or "
        "`wpsecscan mobile-api` both expose this).\n"
        "3. WPSecScan adds a 30-day snooze entry to `~/.wpsecscan/snoozes.json`.\n"
    )


# ---------------------------------------------------------------------------
# H106 — Linear Triage view
# ---------------------------------------------------------------------------

def push_linear_triage(report) -> tuple[bool, str]:
    """Different from the existing --push-linear: puts findings into
    Linear's Triage state instead of an open issue. Operator's
    Triage view becomes the WPSecScan inbox."""
    tok = os.environ.get("LINEAR_API_KEY", "")
    team = os.environ.get("LINEAR_TRIAGE_TEAM_ID", "")
    if not (tok and team):
        return False, "set LINEAR_API_KEY and LINEAR_TRIAGE_TEAM_ID"
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("high", "critical"):
                continue
            q = (
                "mutation { issueCreate(input: { "
                f"teamId: \"{team}\", "
                f"title: \"{f.title.replace(chr(34), chr(39))[:200]}\", "
                f"description: \"WPSecScan\\n{r.check_id}\\n{(f.evidence or '')[:500].replace(chr(34), chr(39))}\", "
                "state: \"triage\" "
                "}) { issue { id } } }"
            )
            try:
                with httpx.Client(timeout=10.0) as c:
                    rr = c.post(
                        "https://api.linear.app/graphql",
                        headers={"Authorization": tok, "Content-Type": "application/json"},
                        json={"query": q},
                    )
                    if rr.status_code == 200:
                        n += 1
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
    return True, f"linear triage: {n} findings pushed"


# ---------------------------------------------------------------------------
# H107 — Asana / ClickUp / Monday push
# ---------------------------------------------------------------------------

def push_asana(report) -> tuple[bool, str]:
    tok = os.environ.get("ASANA_TOKEN", "")
    project = os.environ.get("ASANA_PROJECT_ID", "")
    if not (tok and project):
        return False, "set ASANA_TOKEN + ASANA_PROJECT_ID"
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("high", "critical"):
                continue
            try:
                with httpx.Client(timeout=10.0) as c:
                    rr = c.post(
                        "https://app.asana.com/api/1.0/tasks",
                        headers={"Authorization": f"Bearer {tok}"},
                        json={"data": {
                            "projects": [project],
                            "name": f.title[:120],
                            "notes": f"{r.check_id}\n\n{(f.evidence or '')[:1000]}",
                        }},
                    )
                    if rr.status_code in (200, 201):
                        n += 1
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
    return True, f"asana: {n} tasks created"


def push_clickup(report) -> tuple[bool, str]:
    tok = os.environ.get("CLICKUP_TOKEN", "")
    listid = os.environ.get("CLICKUP_LIST_ID", "")
    if not (tok and listid):
        return False, "set CLICKUP_TOKEN + CLICKUP_LIST_ID"
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("high", "critical"):
                continue
            try:
                with httpx.Client(timeout=10.0) as c:
                    rr = c.post(
                        f"https://api.clickup.com/api/v2/list/{listid}/task",
                        headers={"Authorization": tok, "Content-Type": "application/json"},
                        json={"name": f.title[:120],
                               "description": f"{r.check_id}\n\n{(f.evidence or '')[:1000]}"},
                    )
                    if rr.status_code in (200, 201):
                        n += 1
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
    return True, f"clickup: {n} tasks created"


def push_monday(report) -> tuple[bool, str]:
    tok = os.environ.get("MONDAY_TOKEN", "")
    board = os.environ.get("MONDAY_BOARD_ID", "")
    if not (tok and board):
        return False, "set MONDAY_TOKEN + MONDAY_BOARD_ID"
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("high", "critical"):
                continue
            q = (
                "mutation { create_item ( "
                f"board_id: {board}, "
                f"item_name: \"{f.title.replace(chr(34), chr(39))[:200]}\" "
                ") { id } }"
            )
            try:
                with httpx.Client(timeout=10.0) as c:
                    rr = c.post(
                        "https://api.monday.com/v2",
                        headers={"Authorization": tok, "Content-Type": "application/json"},
                        json={"query": q},
                    )
                    if rr.status_code == 200:
                        n += 1
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
    return True, f"monday: {n} items created"


# ---------------------------------------------------------------------------
# H108 — Statuspage.io incident
# ---------------------------------------------------------------------------

def statuspage_incident(report) -> tuple[bool, str]:
    """When risk_score drops below STATUSPAGE_THRESHOLD (default 50),
    create an investigating-state incident on statuspage.io."""
    tok = os.environ.get("STATUSPAGE_TOKEN", "")
    page = os.environ.get("STATUSPAGE_PAGE_ID", "")
    threshold = int(os.environ.get("STATUSPAGE_THRESHOLD", "50"))
    if not (tok and page):
        return False, "set STATUSPAGE_TOKEN + STATUSPAGE_PAGE_ID"
    if report.risk_score > threshold:
        return False, f"score {report.risk_score} > threshold {threshold}; no incident"
    try:
        with httpx.Client(timeout=10.0) as c:
            r = c.post(
                f"https://api.statuspage.io/v1/pages/{page}/incidents",
                headers={"Authorization": f"OAuth {tok}"},
                json={"incident": {
                    "name": f"Security posture degraded (wpsecscan {report.target})",
                    "status": "investigating",
                    "impact_override": "minor",
                    "body": f"WPSecScan risk score: {report.risk_score}/100",
                }},
            )
            if r.status_code in (200, 201):
                return True, "statuspage incident created"
            return False, f"statuspage: HTTP {r.status_code}"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return False, f"statuspage error: {e}"


# ---------------------------------------------------------------------------
# H109 — PagerDuty AIOps event correlation via dedup_key
# ---------------------------------------------------------------------------

def pagerduty_aiops(report) -> tuple[bool, str]:
    """Push every finding as an Events v2 event with a STABLE dedup_key
    derived from (target, check_id, title), so PagerDuty AIOps groups
    them into a single incident instead of N alert flood."""
    key = os.environ.get("WPSECSCAN_PAGERDUTY_KEY", "")
    if not key:
        return False, "set WPSECSCAN_PAGERDUTY_KEY (Events v2 routing key)"
    import hashlib
    n = 0
    for r in report.results:
        for f in r.findings:
            if f.severity not in ("high", "critical"):
                continue
            dedup = hashlib.sha256(
                f"{report.target}|{r.check_id}|{f.title}".encode()
            ).hexdigest()[:32]
            try:
                with httpx.Client(timeout=10.0) as c:
                    rr = c.post(
                        "https://events.pagerduty.com/v2/enqueue",
                        json={
                            "routing_key": key,
                            "event_action": "trigger",
                            "dedup_key": dedup,
                            "payload": {
                                "summary": f.title[:1024],
                                "source": report.target,
                                "severity": "critical" if f.severity == "critical" else "error",
                                "component": r.check_id,
                            },
                        },
                    )
                    if rr.status_code in (200, 202):
                        n += 1
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
    return True, f"pagerduty: {n} events enqueued"
