"""Round-62 #B22, #B29 — server-side stack reveal + PHP version detect.

Parses every banner-style header WordPress + nginx/Apache + PHP-FPM commonly
leak, then maps versions against EOL data to flag end-of-life software.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


SERVER_PATTERNS = {
    "server":          re.compile(r"^([A-Za-z0-9.\-/+]+)(?:\s+\(([^)]+)\))?", re.IGNORECASE),
    "x-powered-by":    re.compile(r"^([A-Za-z0-9.\-/+]+)", re.IGNORECASE),
    "via":             re.compile(r"^([0-9.]+)\s+([A-Za-z0-9.\-]+)"),
    "x-aspnet-version": re.compile(r"^([0-9.]+)"),
    "x-aspnetmvc-version": re.compile(r"^([0-9.]+)"),
}

# Minimal EOL data — only the most commonly-encountered versions.
PHP_EOL = {
    "5.6": True, "7.0": True, "7.1": True, "7.2": True, "7.3": True,
    "7.4": True, "8.0": True, "8.1": True,  # 8.1 hit EOL 2025-11
    "8.2": False, "8.3": False, "8.4": False,
}
NGINX_EOL = {"1.18": True, "1.20": True, "1.22": True, "1.24": False, "1.26": False, "1.28": False}
APACHE_EOL = {"2.2": True, "2.4": False}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("server-stack reveal: HEAD /...")
    r = await client.head("/")
    if r is None or not r.headers:
        return [Finding(severity="info", title="Stack reveal — no headers returned",
                        evidence="", remediation="No action.", url=ctx["target"])]

    revealed: list[str] = []
    php_version = None
    for hdr_name, pat in SERVER_PATTERNS.items():
        val = r.headers.get(hdr_name, "")
        if not val:
            continue
        m = pat.search(val)
        if not m:
            continue
        revealed.append(f"{hdr_name}: {val[:200]}")
        # Map php version
        if hdr_name == "x-powered-by" and val.lower().startswith("php/"):
            php_version = val.split("/", 1)[1].split(maxsplit=1)[0]

    if revealed:
        findings.append(Finding(
            severity="low",
            title=f"Server-stack reveal ({len(revealed)} banner header(s))",
            evidence="\n".join(f"  {l}" for l in revealed),
            remediation=("Hide via:\n"
                          "  nginx:  server_tokens off; proxy_hide_header X-Powered-By; more_clear_headers Server;\n"
                          "  Apache: ServerTokens Prod; ServerSignature Off; Header unset X-Powered-By;\n"
                          "  PHP:    php_value expose_php Off (php.ini)"),
            url=ctx["target"],
        ))

    if php_version:
        major_minor = ".".join(php_version.split(".")[:2])
        eol = PHP_EOL.get(major_minor)
        if eol is True:
            findings.append(Finding(
                severity="high",
                title=f"PHP {php_version} is end-of-life",
                evidence=f"X-Powered-By header reports PHP/{php_version}; PHP {major_minor} no longer receives security updates.",
                remediation="Upgrade PHP to a supported version (8.3 or later). Check https://www.php.net/supported-versions.php.",
                url=ctx["target"],
            ))
        elif eol is False:
            findings.append(Finding(
                severity="info",
                title=f"PHP {php_version} detected (supported)",
                evidence=f"PHP/{php_version}", remediation="No action.", url=ctx["target"],
            ))

    # nginx / apache EOL pass — same idea against the `server` header
    srv = r.headers.get("server", "")
    if srv.lower().startswith("nginx/"):
        v = srv.split("/", 1)[1].split(maxsplit=1)[0]
        mm = ".".join(v.split(".")[:2])
        if NGINX_EOL.get(mm) is True:
            findings.append(Finding(
                severity="medium",
                title=f"nginx {v} is end-of-life",
                evidence=f"Server header reports nginx/{v}; major.minor {mm} no longer maintained.",
                remediation="Upgrade nginx to a current stable version.",
                url=ctx["target"],
            ))
    if srv.lower().startswith("apache/"):
        v = srv.split("/", 1)[1].split(maxsplit=1)[0]
        mm = ".".join(v.split(".")[:2])
        if APACHE_EOL.get(mm) is True:
            findings.append(Finding(
                severity="high",
                title=f"Apache {v} is end-of-life",
                evidence=f"Server header reports Apache/{v}; {mm} EOL.",
                remediation="Upgrade Apache to 2.4 (current stable). Apache 2.2 hit EOL in 2018.",
                url=ctx["target"],
            ))

    if not findings:
        return [Finding(severity="info", title="Stack reveal — no leaks, all software current",
                        evidence="No revealing banner headers.",
                        remediation="No action.", url=ctx["target"])]
    return findings
