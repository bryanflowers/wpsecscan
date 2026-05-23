"""Error-page fingerprinting.

Probe a deliberately-bad URL and inspect the resulting error response for
disclosed server stack: Apache/Nginx version, PHP version, framework
debug-mode indicators (Symfony, Laravel, Django all have characteristic
error pages).
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Patterns that leak stack info
LEAK_PATTERNS = (
    ("Apache version",  re.compile(r"Apache(?:/| Server at .* Port \d+).*?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Nginx version",   re.compile(r"nginx/(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("PHP version",     re.compile(r"PHP/(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("OpenSSL version", re.compile(r"OpenSSL/(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Symfony debug",   re.compile(r"Symfony [Ee]xception")),
    ("Laravel debug",   re.compile(r"Laravel.+\(\?P\<")),
    ("Whoops debug",    re.compile(r"Whoops, looks like something went wrong")),
    ("Django debug",    re.compile(r"<title>.*at .*</title>.*<h1>.*at .*</h1>")),
    ("Stack trace",     re.compile(r"#0\s+\S+\(\d+\):\s+\S+")),
    ("WP debug trace",  re.compile(r"WP_DEBUG|WordPress database error")),
    ("ERR_NS_FAIL",     re.compile(r"Cannot modify header information")),
)

# Paths that should 404 / 500 on most setups
PROBE_PATHS = (
    "/wpsecscan-canary-does-not-exist",
    "/wp-content/wpsecscan-no-such.php",
    "/?p=999999999999",
    "/?p[]=1",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    discovered: dict[str, list[tuple[str, str]]] = {}  # leak_name -> [(path, sample), ...]
    for path in PROBE_PATHS:
        step(f"probing {path} for error-page disclosures...")
        r = await client.get(path)
        if r is None:
            continue
        body = (r.text or "")[:8000]
        for name, pat in LEAK_PATTERNS:
            for m in pat.finditer(body):
                sample = m.group(0)[:200]
                discovered.setdefault(name, []).append((path, sample))
                break  # one hit per (name, path) is enough
        # Also look at Server / X-Powered-By in headers
        for hk in ("server", "x-powered-by", "x-aspnet-version"):
            v = r.headers.get(hk, "") or r.headers.get(hk.title(), "")
            if v and not v.lower() in ("cloudflare", "nginx", "apache"):  # bare names are fine; versions aren't
                if re.search(r"\d+\.\d+", v):
                    discovered.setdefault(f"{hk} header version leak", []).append((path, f"{hk}: {v}"))

    if not discovered:
        findings.append(
            Finding(
                severity="info",
                title="Error pages don't leak stack/version info",
                evidence=f"Probed {len(PROBE_PATHS)} bad paths; no version strings or debug traces found.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    for name, hits in discovered.items():
        sample_lines = "\n".join(f"  - on {p}: {s!r}" for p, s in hits[:3])
        sev = "high" if "debug" in name.lower() or "trace" in name.lower() else "low"
        findings.append(
            Finding(
                severity=sev,
                title=f"Error page leaks: {name}",
                evidence=f"Pattern detected on {len(hits)} probed path(s):\n{sample_lines}",
                remediation=(
                    "For server-version leaks: suppress with `server_tokens off;` (Nginx) or "
                    "`ServerTokens Prod` + `ServerSignature Off` (Apache).\n"
                    "For PHP debug traces: set `display_errors=Off` and `expose_php=Off` in php.ini; "
                    "in wp-config: `define('WP_DEBUG_DISPLAY', false);` (debug.log only, never to browser)."
                ),
                url=ctx["target"],
            )
        )
    return findings
