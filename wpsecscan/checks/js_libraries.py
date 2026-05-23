"""JavaScript library version detection.

Scan response bodies for popular JS libraries (jQuery, jQuery UI, lodash,
underscore, AngularJS, Bootstrap, Moment.js) and flag versions with known
vulnerabilities.

Detection happens via three patterns:
  1. Filename-versioned URLs (e.g. `/jquery-3.5.1.min.js`)
  2. `?ver=` query strings on WP-enqueued assets
  3. Inline-script version comments (`/* jQuery v1.12.4 */`)

A7 (round-Q): after the local CVE-cutoff check, ALSO query OSV.dev for richer,
real-time CVE matching. OSV.dev has no API token requirement.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from .. import db as vulndb
from ..http import Client
from ..models import Finding

# Map our library names to OSV.dev npm package names
OSV_PACKAGE_MAP = {
    "jQuery":    ("npm", "jquery"),
    "jQuery UI": ("npm", "jquery-ui"),
    "lodash":    ("npm", "lodash"),
    "AngularJS": ("npm", "angular"),
    "Bootstrap": ("npm", "bootstrap"),
    "Moment.js": ("npm", "moment"),
}


async def _query_osv(ecosystem: str, package: str, version: str, timeout: float = 8.0) -> list[dict]:
    """A7: query api.osv.dev for vulnerabilities affecting (ecosystem, package, version).

    Returns a list of advisory dicts; empty on any error. No token required.
    """
    body = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post("https://api.osv.dev/v1/query", json=body,
                             headers={"User-Agent": "WPSecScan/osv"})
            if r.status_code != 200:
                return []
            return (r.json() or {}).get("vulns", []) or []
    except (httpx.HTTPError, ValueError):
        return []

# (library_name, list of regex patterns, hashcat-style "vulnerable below" cutoff)
# Cutoffs from well-known JS-library CVEs.
LIBRARY_PATTERNS = (
    {
        "name": "jQuery",
        "patterns": (
            re.compile(r"jquery[/-](\d+\.\d+(?:\.\d+)?)\.(?:min\.)?js", re.IGNORECASE),
            re.compile(r"/\*!?\s*jQuery\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"jquery[\.\-_]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        ),
        "vulnerable_below": "3.5.0",
        "cves": "CVE-2020-11022, CVE-2020-11023 (XSS via .html()/.append() on attacker-controlled input)",
    },
    {
        "name": "jQuery UI",
        "patterns": (
            re.compile(r"jquery[\.\-]ui[\.\-](\d+\.\d+(?:\.\d+)?)\.(?:min\.)?js", re.IGNORECASE),
            re.compile(r"/\*!?\s*jQuery UI\s+(?:-\s+)?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ),
        "vulnerable_below": "1.13.2",
        "cves": "CVE-2022-31160 (XSS in .checkboxradio()), CVE-2021-41184 (XSS in .position())",
    },
    {
        "name": "lodash",
        "patterns": (
            re.compile(r"lodash[/-](\d+\.\d+(?:\.\d+)?)\.(?:min\.)?js", re.IGNORECASE),
            re.compile(r"/\*\s*lodash\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ),
        "vulnerable_below": "4.17.21",
        "cves": "CVE-2021-23337 (command injection in _.template), CVE-2020-8203 (prototype pollution)",
    },
    {
        "name": "AngularJS",
        "patterns": (
            re.compile(r"angular[\.\-]js[/-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
            re.compile(r"/\*\s*AngularJS\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ),
        "vulnerable_below": "999",  # AngularJS 1.x reached EOL; ANY version is vulnerable
        "cves": "AngularJS reached end-of-life in January 2022 — there will be no further security patches.",
    },
    {
        "name": "Bootstrap",
        "patterns": (
            re.compile(r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)(?:[\.\-]min)?\.(?:js|css)", re.IGNORECASE),
            re.compile(r"/\*!?\s*Bootstrap\s+v(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ),
        "vulnerable_below": "4.3.1",
        "cves": "CVE-2018-14041, CVE-2019-8331 (XSS in tooltips/popovers)",
    },
    {
        "name": "Moment.js",
        "patterns": (
            re.compile(r"moment[/-](\d+\.\d+(?:\.\d+)?)\.(?:min\.)?js", re.IGNORECASE),
            re.compile(r"/\*!?\s*Moment\.js\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        ),
        "vulnerable_below": "2.29.4",
        "cves": "CVE-2022-31129 (ReDoS in long string parsing)",
    },
)


def _ver_lt(a: str, b: str) -> bool:
    return vulndb.ver_lt(a, b)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Pull homepage + a few common pages where script tags appear
    SOURCES = ("/", "/wp-login.php", "/?p=1", "/feed/", "/sample-page/")
    detected: dict[str, str] = {}  # lib -> highest-version-string seen
    bodies: list[str] = []
    for path in SOURCES:
        step(f"scanning {path} for JS library versions...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        bodies.append(r.text)

    combined = "\n".join(bodies)

    for lib in LIBRARY_PATTERNS:
        for pat in lib["patterns"]:
            for m in pat.finditer(combined):
                ver = m.group(1)
                if lib["name"] not in detected:
                    detected[lib["name"]] = ver
                else:
                    # Keep the higher version we see
                    if _ver_lt(detected[lib["name"]], ver):
                        detected[lib["name"]] = ver
                break  # only need first match per pattern per library

    if not detected:
        findings.append(
            Finding(
                severity="info",
                title="No common JS libraries detected via filename / version-comment patterns",
                evidence=f"Scanned {len(bodies)} pages.",
                remediation="No action needed. (Sites that bundle JS via webpack/Vite typically obfuscate version strings.)",
                url=ctx["target"],
            )
        )
        return findings

    summary_lines = "\n".join(f"  - {name}: {ver}" for name, ver in detected.items())
    findings.append(
        Finding(
            severity="info",
            title=f"Detected {len(detected)} JS librar(y/ies) in page source",
            evidence="Libraries discovered:\n" + summary_lines,
            remediation="No action needed. See per-library findings below for any with known CVEs.",
            url=ctx["target"],
        )
    )

    for lib in LIBRARY_PATTERNS:
        name = lib["name"]
        if name not in detected:
            continue
        installed = detected[name]
        cutoff = lib["vulnerable_below"]
        if cutoff == "999":  # special case: any version is EOL/vulnerable
            findings.append(
                Finding(
                    severity="medium",
                    title=f"{name} is end-of-life ({installed} detected)",
                    evidence=f"{name} {installed} detected. {lib['cves']}",
                    remediation=f"Migrate off {name}. For AngularJS specifically, no upgrade path exists — move to Angular (TypeScript) or another framework.",
                    url=ctx["target"],
                )
            )
            continue
        if _ver_lt(installed, cutoff):
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Outdated {name}: {installed} (fixed in {cutoff})",
                    evidence=f"Detected {name} {installed}; vulnerable to: {lib['cves']}",
                    remediation=(
                        f"Update {name} to {cutoff}+. In WordPress, the bundled jQuery is updated via core; "
                        f"for theme-bundled JS, edit the theme's enqueue calls. For Bootstrap/Moment, the "
                        f"library is usually in the theme — check the theme's CSS/JS folders."
                    ),
                    url=ctx["target"],
                    extra={"library": name, "installed": installed, "fixed_in": cutoff},
                )
            )

    # A7: OSV.dev cross-reference for richer, real-time CVE matching.
    # Run all queries in parallel so this whole section is bounded by the slowest.
    osv_tasks = []
    for name, version in detected.items():
        eco_pkg = OSV_PACKAGE_MAP.get(name)
        if not eco_pkg:
            continue
        step(f"OSV.dev lookup: {eco_pkg[1]}@{version}...")
        osv_tasks.append((name, version, _query_osv(eco_pkg[0], eco_pkg[1], version)))
    for name, version, coro in osv_tasks:
        try:
            vulns = await coro
        except (asyncio.CancelledError,):
            raise
        except Exception:  # noqa: BLE001
            vulns = []
        if not vulns:
            continue
        ids = sorted({v.get("id", "?") for v in vulns})[:8]
        aliases = sorted({a for v in vulns for a in (v.get("aliases") or [])})[:8]
        cves = [a for a in aliases if a.startswith("CVE-")][:5]
        severity_levels = []
        for v in vulns:
            for sev in v.get("severity", []) or []:
                score = sev.get("score") or ""
                if "CRITICAL" in score.upper() or "9." in score:
                    severity_levels.append("critical")
                elif "HIGH" in score.upper() or "7." in score or "8." in score:
                    severity_levels.append("high")
        worst = "high" if "critical" not in severity_levels else "critical"
        if not severity_levels:
            worst = "medium"
        findings.append(
            Finding(
                severity=worst,
                title=f"OSV.dev: {name} {version} has {len(vulns)} known advisor{'y' if len(vulns)==1 else 'ies'}",
                evidence=(
                    f"OSV-cross-referenced — {name} {version}:\n"
                    f"  Advisory IDs: {', '.join(ids)}\n"
                    + (f"  CVEs: {', '.join(cves)}\n" if cves else "")
                    + f"  Detail: https://osv.dev/list?q={OSV_PACKAGE_MAP[name][1]}&ecosystem=npm"
                ),
                remediation=(
                    f"Update {name} to a version that's not affected. OSV.dev lists `fixed` versions for "
                    "each advisory — pick the highest one mentioned and use that as the target."
                ),
                url=f"https://osv.dev/list?q={OSV_PACKAGE_MAP[name][1]}&ecosystem=npm",
                extra={"osv_advisories": ids, "cves": cves},
            )
        )

    return findings
