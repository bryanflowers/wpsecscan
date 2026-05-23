# WPSecScan — Embeddable SDK

WPSecScan is importable as a Python library. Use it to embed scanning into
your own tools, CI pipelines, or custom dashboards.

## Install

```bash
pip install httpx[http2] jinja2 rich openpyxl
git clone https://github.com/bryan/wpsecscan.git
pip install -e ./wpsecscan
```

(PyPI release pending — for now install from source.)

## 30-second example

```python
import asyncio
from wpsecscan import scan
from wpsecscan.reporters import json_out, html as html_reporter

async def main():
    report = await scan(
        "https://your-wp-site.com",
        aggressive=False,           # passive only
        timeout=15.0,
        concurrency=10,
    )
    print(f"Risk score: {report.risk_score}/100")
    for r in report.results:
        for f in r.findings:
            if f.severity in ("critical", "high"):
                print(f"  [{f.severity.upper()}] {f.title}")

    # Save reports
    from pathlib import Path
    Path("report.html").write_text(html_reporter.render(report), encoding="utf-8")
    Path("report.json").write_text(json_out.render(report), encoding="utf-8")

asyncio.run(main())
```

## Public API surface

### Top-level

```python
from wpsecscan import scan
# scan(target, *, timeout=15.0, user_agent=..., concurrency=10,
#      verify_tls=True, wpscan_token=None, hibp_token=None,
#      aggressive=False, prove=False, sequential=True,
#      auth_user=None, auth_pass=None, deep_throttle=False,
#      deep_throttle_attempts=120, deep_throttle_pacing_s=10.0,
#      har=False, har_path=None, parallel_groups=False, checkpoint=False,
#      abuseipdb_token=None, vt_token=None, github_search_token=None,
#      on_progress=None, is_cancelled=None) -> ScanReport
```

### Models

```python
from wpsecscan.models import ScanReport, CheckResult, Finding, SEVERITIES
# Finding(severity, title, evidence="", remediation="", url="", extra={})
# CheckResult(check_id, check_name, findings=[], error=None, duration_ms=0)
# ScanReport(target, scanned_at, duration_ms, results=[])
#   .summary -> {sev: count}
#   .risk_score -> int 0-100
#   .all_findings -> [Finding, ...]
```

### Reporters

```python
from wpsecscan.reporters import (
    console as console_reporter,   # rich-formatted terminal output
    html as html_reporter,         # HTML with risk banner + exploit playbooks
    json_out as json_reporter,     # JSON with KEV/EPSS/CWE/compliance enrichment
    markdown as md_reporter,       # GitHub-flavored markdown
    csv_out as csv_reporter,       # formula-injection-safe CSV
    sarif as sarif_reporter,       # SARIF 2.1.0 for GitHub Code Scanning
    xlsx_out as xlsx_reporter,     # XLSX with per-OWASP-category sheets
)
# Every reporter exposes:
#   render(report: ScanReport) -> str | bytes
#   write(report: ScanReport, path: Path) -> None
```

### Integrations

```python
from wpsecscan.integrations import (
    cisa_kev,        # cisa_kev.is_kev("CVE-2024-1234") -> bool
    epss,            # epss.lookup_scores(["CVE-2024-1234"]) -> {cve: {epss, percentile}}
    virustotal,      # virustotal.lookup_url(url, token) / lookup_ip(ip, token)
    sucuri_sitecheck,  # sucuri_sitecheck.lookup(target) -> dict
    github_issues,   # github_issues.create_issues_for_report(report, repo, token)
)
```

### Custom checks (drop-in plugins)

Create `~/.wpsecscan/plugins/my_check.py`:

```python
from wpsecscan.models import Finding

CHECK_ID = "my_company_specific_check"
CHECK_NAME = "MyCompany custom check"
IS_AGGRESSIVE = False

async def check(client, ctx):
    r = await client.get("/our-internal-endpoint")
    if r is None:
        return []
    if r.status_code == 200 and "DEBUG_MODE" in (r.text or ""):
        return [Finding(
            severity="high",
            title="Internal debug endpoint exposed",
            evidence=f"GET /our-internal-endpoint -> {r.status_code}",
            remediation="Disable internal debug mode in production.",
            url=ctx["target"],
        )]
    return []
```

The check is auto-discovered on the next scan.

### Custom signatures / payloads

Drop JSON files in `~/.wpsecscan/signatures/` (auto-merged into the signature DB)
or `~/.wpsecscan/payloads/` (auto-merged into the payload library).

Schema matches `wpsecscan/data/exploit_signatures.json` and `wpsecscan/data/payloads.json`.
Custom payloads MUST have `"read_only": true` — the loader rejects write-side payloads.

### Progress callbacks

```python
def on_progress(event, check_id, check_name, result):
    # event in {"start", "step", "done"}
    print(f"{event}: {check_id} - {check_name}")

await scan("https://x.com", on_progress=on_progress)
```

### Cancellation

```python
import threading
cancel_flag = threading.Event()
report = await scan("https://x.com", is_cancelled=lambda: cancel_flag.is_set())
# Long-running checks (deep_throttle, sitemap probes) poll is_cancelled() and bail gracefully.
```

## Stability promise

- **stable**: `scan()`, `Finding`, `CheckResult`, `ScanReport`, all reporters' `render()` + `write()`
- **stable**: integration module function names (`cisa_kev.is_kev`, `epss.lookup_scores`, etc.)
- **unstable**: anything starting with `_`, anything in `wpsecscan.gui*`, `wpsecscan.daemon`

Breaking changes to `scan()` will only happen at major version bumps and will be flagged in the CHANGELOG.
