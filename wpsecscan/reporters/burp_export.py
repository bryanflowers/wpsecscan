"""D7 — Burp Suite handoff.

Produces a Burp Suite scope+sitemap XML that the user can import into Burp
(File -> Project options -> Target -> Scope -> Load). All discovered URLs
become in-scope; the target host gets an included-prefix rule.

This is a *minimal* Burp project format — just the scope + a flat list of
hostnames found during the scan. Full sitemap (with HTTP messages) would
require capturing the full request/response, which is what `--har` is for.

Use the workflow:
  1. wpsecscan https://target.com --har trace.har
  2. wpsecscan ... --burp-export burp_scope.xml
  3. In Burp: import the scope, then "Import" the HAR file from Burp's
     Proxy → HTTP history → right-click → Import requests from HAR.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from ..models import ScanReport


def render(report: ScanReport) -> str:
    """Produce a Burp-compatible scope XML."""
    parsed = urlparse(report.target)
    apex_host = parsed.hostname or "example.com"
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)

    # Collect every URL referenced in the report (including ones from findings)
    extra_hosts: set[str] = set()
    for r in report.results:
        for f in r.findings:
            if f.url:
                try:
                    h = urlparse(f.url).hostname
                    if h and h != apex_host:
                        extra_hosts.add(h)
                except (ValueError, TypeError):
                    continue

    rules_xml = [
        f'    <rule><enabled>true</enabled><protocol>{escape(scheme)}</protocol>'
        f'<host>{escape(apex_host)}</host><port>{port}</port>'
        f'<file>.*</file></rule>'
    ]
    for h in sorted(extra_hosts):
        rules_xml.append(
            f'    <rule><enabled>true</enabled><protocol>any</protocol>'
            f'<host>{escape(h)}</host><port>0</port><file>.*</file></rule>'
        )

    return (
        '<?xml version="1.0"?>\n'
        '<!--\n'
        f'  WPSecScan -> Burp Suite handoff scope file.\n'
        f'  Source: {escape(report.target)}\n'
        f'  Generated: {escape(report.scanned_at)}\n'
        f'  Risk score: {report.risk_score}/100\n'
        '\n'
        '  Import via: Project options -> Target -> Scope -> Load.\n'
        '-->\n'
        '<scope>\n'
        '  <include>\n'
        + "\n".join(rules_xml) +
        '\n  </include>\n'
        '  <exclude/>\n'
        '</scope>\n'
    )


def write(report: ScanReport, path: Path) -> None:
    # v2.8.3 H3 — atomic temp+rename via shared helper.
    from . import _atomic_write_text
    _atomic_write_text(path, render(report))
    try:
        from .. import activity as _act
        _act.emit("reporter", f"Burp scope: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
