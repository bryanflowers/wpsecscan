"""Detect Real-User-Monitoring (RUM) beacon libraries in page source.

RUM beacons send full URL paths (including query strings) plus timing
data to vendor cloud endpoints. The query strings may include
sensitive identifiers like ?email=, ?reset_key=, ?token= that the
site owner thought were transient. Privacy inventory item.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


# (vendor name, regex matching the loader/init pattern)
_RUM_VENDORS = (
    ("New Relic Browser",  re.compile(r"\b(NREUM|newrelic\.com/nr-)\b")),
    ("Datadog RUM",        re.compile(r"\b(DD_RUM|datadoghq\.com/rum-)\b")),
    ("Dynatrace",          re.compile(r"\b(dtrum|dynatrace\.com/rb)\b")),
    ("SpeedCurve LUX",     re.compile(r"\bLUX\b\s*=\s*\{|speedcurve\.com/lux")),
    ("Sentry Browser",     re.compile(r"\b(Sentry\.init|sentry-cdn\.com)\b")),
    ("Cloudflare RUM",     re.compile(r"static\.cloudflareinsights\.com")),
    ("Akamai mPulse",      re.compile(r"akamaihd\.net/mpulse")),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("scanning homepage for RUM beacon libraries...")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    detected: list[str] = []
    for name, rx in _RUM_VENDORS:
        if rx.search(r.text):
            detected.append(name)
    if not detected:
        return findings
    findings.append(Finding(
        severity="low",
        title=f"Real-User-Monitoring beacon(s) active: {', '.join(detected)}",
        evidence=(
            f"Detected RUM library/libraries in homepage source: {', '.join(detected)}\n\n"
            "RUM beacons send the full visited URL (including query strings) plus "
            "timing data to the vendor's cloud endpoint. If your site uses URL "
            "parameters for password-reset keys, magic-login links, account-"
            "switch tokens, etc., those parameters end up in the RUM provider's "
            "log — outside your control."
        ),
        remediation=(
            "Privacy inventory item — verify each vendor is on your data-processor "
            "list (GDPR Article 28 / DPA). Audit whether sensitive query-string "
            "parameters (?email=, ?token=, ?reset_key=) flow through pages where "
            "the RUM library is active. Most RUM vendors support URL-redaction "
            "filters — configure them."
        ),
        url=ctx["target"],
        extra={"rum_vendors": detected},
    ))
    return findings
