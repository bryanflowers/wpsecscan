"""Round-56 `--demo` mode.

Synthesises a fake ScanReport with ~30 findings across every severity +
every OWASP category, and emits ~40 activity events at realistic intervals
so the user can see the full live dashboard + every category badge.

No HTTP traffic. No real target. Output artifacts (HTML / JSON / MD / XLSX /
SBOM / attestation / etc.) are written to `~/.wpsecscan/demo/` so the user
can open each one to see what a real scan produces.

Use cases:
  * README / docs screenshots
  * smoke-test after install
  * training new users without scanning a real site
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path

from . import activity as _act
from .models import CheckResult, Finding, ScanReport


DEMO_TARGET = "https://wpsecscan-demo.invalid"


# (check_id, check_name, list of (sev, title))
DEMO_RESULTS = [
    ("waf",           "WAF / CDN detection", [
        ("info", "Cloudflare detected (cf-ray header present)"),
    ]),
    ("core_version",  "WordPress core version", [
        ("low",  "WP 6.5.2 — one minor behind 6.5.3"),
    ]),
    ("plugins",       "Plugin enumeration", [
        ("info", "12 plugins identified (woocommerce 9.2.1, elementor 3.21.4, …)"),
    ]),
    ("subdomains",    "Subdomain discovery", [
        ("info", "34 subdomains via certificate transparency"),
        ("low",  "3 subdomain(s) with sensitive labels (staging, dev)"),
    ]),
    ("cors",          "CORS misconfiguration", [
        ("high",   "CORS reflects null origin at /wp-json/wp/v2/posts"),
        ("medium", "CORS preflight reflects attacker origin at /wp-json/"),
    ]),
    ("rest_api",      "WP REST API surface audit", [
        ("medium", "REST /wp-json/wp/v2/users exposes 14 user logins unauth"),
    ]),
    ("plugin_cves",   "Plugin CVE matching", [
        ("critical", "elementor 3.21.4 — CVE-2024-1234 (RCE via file upload)"),
        ("high",     "woocommerce 9.2.1 — CVE-2024-5678 (SQLi in REST endpoint)"),
    ]),
    ("sqli",          "SQL injection probes", [
        ("critical", "CONFIRMED time-blind SQLi at /?p= via UNION → pg_sleep(5)"),
    ]),
    ("cloud_metadata_ssrf", "Cloud-metadata SSRF chain", [
        ("critical", "CONFIRMED cloud-metadata SSRF — AWS IMDSv1 reachable"),
    ]),
    ("xss_reflected", "Reflected XSS probes", [
        ("high",   "CONFIRMED reflected XSS at /?s= (CSP bypass via <svg/onload>)"),
    ]),
    ("jwt_audit",     "JWT audit", [
        ("critical", "Server accepts `alg=none` JWT — full auth bypass"),
    ]),
    ("dom_xss_headless", "Headless DOM-XSS (Playwright)", [
        ("critical", "CONFIRMED client-side DOM-XSS via URLSearchParams.innerHTML sink"),
    ]),
    ("github_leak_search", "GitHub leaked-token search", [
        ("critical", "Possible AWS Access Key leak: example.com mentioned in attacker/repo/.env"),
    ]),
    ("session_fixation", "Session-fixation precondition probe", [
        ("medium", "3 session cookie(s) accepted client-set value without regenerating"),
    ]),
    ("csrf_entropy",  "CSRF nonce entropy sampler", [
        ("low",    "Average per-nonce entropy 3.21 bits/char (expected ~5.95)"),
    ]),
    ("backup_file_fuzz", "Backup-file long-tail fuzzer", [
        ("high",   "/wp-config.php~ reachable (vim backup)"),
        ("medium", "/.vscode/settings.json reachable"),
    ]),
    ("tls_headers",   "TLS & security headers", [
        ("medium", "HSTS header missing"),
        ("low",    "X-Frame-Options absent (clickjacking risk)"),
    ]),
    ("csp",           "CSP deep analysis", [
        ("medium", "Content-Security-Policy header absent"),
    ]),
    ("cookies",       "Cookie hardening", [
        ("medium", "Session cookie missing SameSite + HttpOnly"),
    ]),
    ("dns_security",  "DNS security (SPF/DMARC/DKIM)", [
        ("medium", "DMARC policy p=none (audit mode — emails can be spoofed)"),
    ]),
    ("favicon_fingerprint", "Favicon fingerprint", [
        ("info",   "Favicon hash 0xabcd1234 → WordPress core default"),
    ]),
    ("debug_leaks",   "Debug & info leaks", [
        ("info",   "X-Powered-By: PHP/8.2.7 disclosed"),
    ]),
    ("robots_sitemap", "robots.txt / sitemap audit", [
        ("info",   "Sitemap /wp-sitemap.xml found — 247 URLs"),
    ]),
]


# Activity events to fire during the demo, in order. Real scans interleave
# these with findings; the demo fires them at fixed intervals so every
# category badge appears in the live dashboard.
DEMO_ACTIVITY = [
    ("integration", "audit log: scan started → https://wpsecscan-demo.invalid"),
    ("governance",  "region egress: eu-west-1 → http://eu-proxy:3128"),
    ("threat_intel","CISA KEV catalog refreshed (1247 CVEs)"),
    ("meta",        "update available: v1.3.0 (you're on v1.2.4)"),
    ("threat_intel","EPSS scored 14 CVE(s) · 11 cache hit(s), 3 fetched"),
    ("threat_intel","CVE writeup fetched: CVE-2024-1234 (NVD)"),
    ("threat_intel","VirusTotal IP 203.0.113.5: 0 malicious / US"),
    ("threat_intel","Sucuri SiteCheck: clean"),
    ("integration", "redis cache hit (cve_scoring · 847 ms saved)"),
    ("integration", "OTel span emitted"),
    ("meta",        "incremental skip: favicon_fingerprint (no change since 2026-05-20)"),
    ("meta",        "check auto-disabled: js_supply_chain (3 consecutive failures)"),
    ("artifact",    "screenshots captured: 5 critical/high finding(s)"),
    ("reporter",    "HTML: wpsec-demo.html (1248 KB)"),
    ("reporter",    "JSON: wpsec-demo.json (47 KB)"),
    ("reporter",    "Markdown: wpsec-demo.md (62 KB)"),
    ("reporter",    "Excel: wpsec-demo.xlsx (38 KB)"),
    ("reporter",    "SARIF: wpsec-demo.sarif (51 KB)"),
    ("reporter",    "Burp scope: wpsec-demo-burp-scope.xml (3 KB)"),
    ("reporter",    "Executive PDF: wpsec-demo-exec.pdf"),
    ("reporter",    "Attestation PDF: wpsec-demo-att.pdf"),
    ("artifact",    "SBOM: bom.json (124 components)"),
    ("artifact",    "auto-PR script: 6 fix(es) → wpsec-demo-auto-pr.sh"),
    ("integration", "audit log → splunk (ok)"),
    ("integration", "audit log: scan complete · risk 41"),
]


def build_demo_report() -> ScanReport:
    """Return a fully-formed ScanReport with the synthetic findings."""
    results: list[CheckResult] = []
    for cid, cname, finding_specs in DEMO_RESULTS:
        cr = CheckResult(
            check_id=cid,
            check_name=cname,
            findings=[Finding(severity=sev, title=title, evidence="(demo)",
                              remediation="(demo)", url=DEMO_TARGET)
                      for sev, title in finding_specs],
            duration_ms=120 + (hash(cid) % 800),  # 120–920 ms per check, deterministic
        )
        results.append(cr)
    # Add a few skipped checks so the "What ran" panel shows incremental + auto-disable lines
    results.append(CheckResult(check_id="favicon_fingerprint", check_name="Favicon fingerprint",
                                error="Skipped: incremental mode — no target change since baseline.",
                                duration_ms=0))
    results.append(CheckResult(check_id="js_supply_chain", check_name="External JS supply-chain",
                                error="auto-disabled this run after repeated failures",
                                duration_ms=12))
    return ScanReport(
        target=DEMO_TARGET,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_ms=12_800,
        results=results,
    )


async def run_demo_async(*, console=None, paced: bool = True,
                          interval_s: float = 0.08) -> ScanReport:
    """Build the demo report and drip-emit activity events.

    paced=True streams events with `interval_s` gap so the user sees the
    activity feed scroll. Used by CLI live dashboard.
    paced=False fires all events immediately — for tests / GUI demo where
    pacing is handled by the consumer.
    """
    _act.clear()
    report = build_demo_report()

    # Emit synthetic per-check progress events too, so the live dashboard's
    # findings panel populates as if a real scan were happening.
    for cr in report.results:
        if cr.error:
            continue
        for f in cr.findings:
            _act.emit("check", f"[{f.severity.upper()}] {cr.check_id}: {f.title[:60]}")
            if paced:
                await asyncio.sleep(interval_s)

    for cat, msg in DEMO_ACTIVITY:
        _act.emit(cat, msg)
        if paced:
            await asyncio.sleep(interval_s)

    return report


def run_demo(*, paced: bool = True) -> ScanReport:
    """Synchronous wrapper. Returns the synthesised report."""
    return asyncio.run(run_demo_async(paced=paced))


def write_artifacts(report: ScanReport, out_dir: Path) -> dict[str, Path]:
    """Write every reporter's output for the demo report under `out_dir`.
    Returns a dict of {format: path}. Each successful write also fires its
    own activity event via the reporter's own emit hook."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = "wpsec-demo"
    written: dict[str, Path] = {}

    def _try(fmt: str, suffix: str, writer):
        p = out_dir / f"{stem}{suffix}"
        try:
            writer(p)
            written[fmt] = p
        except Exception:  # noqa: BLE001
            pass

    from .reporters import html as _h, json_out as _j, csv_out as _c
    from .reporters import sarif as _s, markdown as _m
    _try("html",     ".html",     lambda p: _h.write(report, p))
    _try("json",     ".json",     lambda p: _j.write(report, p))
    _try("csv",      ".csv",      lambda p: _c.write(report, p))
    _try("sarif",    ".sarif",    lambda p: _s.write(report, p))
    _try("markdown", ".md",       lambda p: _m.write(report, p))
    try:
        from .reporters import xlsx_out as _x
        _try("xlsx", ".xlsx", lambda p: _x.write(report, p))
    except ImportError:
        pass
    try:
        from .reporters import burp_export as _b
        _try("burp", "-burp-scope.xml", lambda p: _b.write(report, p))
    except ImportError:
        pass
    try:
        from .reporters import exec_pdf as _epdf
        _try("exec_pdf", "-exec.pdf", lambda p: _epdf.write(report, p))
    except ImportError:
        pass
    try:
        from .reporters import attestation as _att
        _try("attestation", "-att.pdf",
             lambda p: _att.write(report, p, vendor="DemoCo", customer="ExampleCorp"))
    except ImportError:
        pass
    try:
        from . import sbom as _sb
        _try("sbom", "-sbom.json", lambda p: _sb.write(p, scanner_version="demo"))
    except ImportError:
        pass
    try:
        from . import auto_pr as _ap
        _try("auto_pr", "-auto-pr.sh",
             lambda p: _ap.write_script(report, p, repo="example-org/example-site"))
    except ImportError:
        pass
    return written
