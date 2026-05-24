"""Round-59 #83-86 — Plugin-developer outreach helpers.

Templates and structured payloads for coordinated disclosure to plugin
authors, the wp.org plugin team, Patchstack, and CVE numbering
authorities. All pure functions — no network.

#83 Coordinated disclosure helper — `disclosure_email(finding, vendor)`
    returns a polite, structured-disclosure email body.
#84 wp.org submission helper — `wporg_submission(finding, slug)` builds
    a Trac ticket payload following the wp.org plugin-team format.
#85 Patchstack vendor helper — `patchstack_submission(finding, vendor)`
    builds a JSON payload for Patchstack's MVDP form.
#86 CVE assignment helper — `cve_request(finding, vendor)` builds a CNA
    JSON record per CVE 5.1 schema (https://cveproject.github.io/cve-schema/).
"""
from __future__ import annotations

import datetime
import json
from typing import Any


def _f(finding: Any, attr: str, default: str = "") -> str:
    """Tolerant getter — works on Finding dataclass OR plain dict."""
    if finding is None:
        return default
    if isinstance(finding, dict):
        return str(finding.get(attr) or default)
    return str(getattr(finding, attr, default) or default)


def disclosure_email(finding: Any, vendor: str, reporter_name: str = "WPSecScan operator",
                       reporter_email: str = "security@example.com") -> str:
    """#83 — RFC-style coordinated-disclosure email body."""
    title = _f(finding, "title")
    sev = _f(finding, "severity")
    ev = _f(finding, "evidence")[:1500]
    rem = _f(finding, "remediation")[:1500]
    url = _f(finding, "url")
    today = datetime.date.today().isoformat()
    return (
        f"Subject: Security disclosure — {title}\n\n"
        f"Hello {vendor} security team,\n\n"
        f"I am reaching out to coordinate disclosure of a {sev.upper()}-severity issue "
        f"affecting your software, identified by an automated scan on {today}.\n\n"
        f"Affected URL: {url}\n\n"
        f"=== Issue ===\n{title}\n\n"
        f"=== Evidence ===\n{ev}\n\n"
        f"=== Suggested remediation ===\n{rem}\n\n"
        f"I'm following industry standard 90-day coordinated disclosure. I will not "
        f"disclose technical details publicly before {(datetime.date.today() + datetime.timedelta(days=90)).isoformat()} "
        f"unless we mutually agree on an earlier date or you do not respond within 14 days.\n\n"
        f"Please confirm receipt at your earliest convenience.\n\n"
        f"Regards,\n{reporter_name}\n{reporter_email}\n"
    )


def wporg_submission(finding: Any, slug: str) -> dict:
    """#84 — Trac-ticket-shaped payload for the wp.org plugin team
    (https://make.wordpress.org/plugins/handbook/plugin-security/)."""
    return {
        "to": "plugins@wordpress.org",
        "subject": f"[Plugin Security] {slug} — {_f(finding, 'title')}",
        "body": (
            f"Plugin slug: {slug}\n"
            f"Severity: {_f(finding, 'severity')}\n"
            f"Affected URL: {_f(finding, 'url')}\n\n"
            f"Title: {_f(finding, 'title')}\n\n"
            f"Evidence:\n{_f(finding, 'evidence')[:2000]}\n\n"
            f"Suggested fix:\n{_f(finding, 'remediation')[:2000]}\n\n"
            f"Reported via WPSecScan. Following wp.org plugin-team coordinated disclosure."
        ),
    }


def patchstack_submission(finding: Any, vendor: str) -> dict:
    """#85 — Patchstack MVDP form payload."""
    return {
        "vendor": vendor,
        "title": _f(finding, "title"),
        "severity": _f(finding, "severity"),
        "url": _f(finding, "url"),
        "description": _f(finding, "evidence")[:5000],
        "remediation": _f(finding, "remediation")[:5000],
        "discovered_by": "WPSecScan",
        "discovered_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "form_url": "https://patchstack.com/database/submit-vulnerability/",
    }


def cve_request(finding: Any, vendor: str, product: str,
                 affected_versions: list[str] | None = None) -> dict:
    """#86 — CVE 5.1 JSON record. Empty CVE-ID — your CNA assigns it."""
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": "",  # CNA fills in
            "assignerOrgId": "",  # CNA fills in
            "state": "PUBLISHED",
        },
        "containers": {
            "cna": {
                "title": _f(finding, "title"),
                "descriptions": [{"lang": "en",
                                    "value": _f(finding, "evidence")[:3000]}],
                "affected": [{
                    "vendor": vendor,
                    "product": product,
                    "versions": [{"version": v, "status": "affected"}
                                    for v in (affected_versions or ["unspecified"])],
                }],
                "problemTypes": [{
                    "descriptions": [{"lang": "en", "type": "text",
                                       "description": _f(finding, "title")}],
                }],
                "providerMetadata": {"orgId": ""},
                "metrics": [{"format": "CVSS",
                              "scenarios": [{"lang": "en",
                                              "value": f"severity={_f(finding, 'severity')}"}]}],
            },
        },
        "solution": _f(finding, "remediation")[:3000],
        "_note": "Submit to https://cveform.mitre.org/ or your CNA's intake form.",
    }


def export_bundle(finding: Any, vendor: str, slug: str, product: str) -> str:
    """Build a single JSON containing all four payloads. Useful for one-click
    "disclose everywhere" workflow."""
    return json.dumps({
        "disclosure_email": disclosure_email(finding, vendor),
        "wporg_submission": wporg_submission(finding, slug),
        "patchstack": patchstack_submission(finding, vendor),
        "cve_request": cve_request(finding, vendor, product),
    }, indent=2, default=str)
