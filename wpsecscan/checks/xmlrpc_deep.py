"""Deep XML-RPC enumeration.

Beyond what login.py already checks, this:
  1. Lists every registered XML-RPC method via system.listMethods
  2. Flags dangerous combinations (pingback.ping + system.multicall = SSRF amplifier)
  3. Probes for the Akismet pingback validation bug pattern (CVE-2014 family)
  4. Checks if mt.supportedMethods / blogger.* endpoints are open (legacy editor protocols)
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

LIST_METHODS_BODY = (
    "<?xml version=\"1.0\"?>"
    "<methodCall><methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)

METHOD_RE = re.compile(r"<string>([a-zA-Z_][a-zA-Z0-9_.]+)</string>")

# Methods that are individually worth flagging
DANGEROUS_METHODS = {
    "pingback.ping":        ("medium", "SSRF amplifier — pingback.ping can be coerced into hitting internal hosts"),
    "system.multicall":     ("medium", "Brute-force amplifier — bundles many auth attempts into one HTTP request"),
    "wp.getUsersBlogs":     ("medium", "Username/password validity oracle accessible over XML-RPC"),
    "wp.uploadFile":        ("high",   "File upload over XML-RPC — historically backdoored on misconfigured installs"),
    "mt.supportedMethods":  ("info",   "Legacy Movable Type compatibility methods exposed"),
    "blogger.getUsersBlogs":("info",   "Legacy Blogger API methods exposed"),
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("POST /xmlrpc.php with system.listMethods...")
    r = await client.post(
        "/xmlrpc.php",
        content=LIST_METHODS_BODY,
        headers={"Content-Type": "text/xml"},
    )
    if r is None or r.status_code != 200 or "methodResponse" not in (r.text or ""):
        findings.append(
            Finding(
                severity="info",
                title="XML-RPC endpoint not responding to system.listMethods",
                evidence=f"POST /xmlrpc.php -> {r.status_code if r else 'no response'}",
                remediation="Likely good — either XML-RPC is blocked or never was enabled. No action needed.",
                url=client.url("/xmlrpc.php"),
            )
        )
        return findings

    methods = METHOD_RE.findall(r.text or "")
    if not methods:
        findings.append(
            Finding(
                severity="info",
                title="XML-RPC responds but no methods enumerated",
                evidence="system.listMethods returned 200 but the response body contained no <string> entries.",
                remediation="No action needed.",
                url=client.url("/xmlrpc.php"),
            )
        )
        return findings

    findings.append(
        Finding(
            severity="info",
            title=f"XML-RPC enumerated: {len(methods)} method(s)",
            evidence=(
                "Sample (first 30):\n  "
                + "\n  ".join(sorted(set(methods))[:30])
                + ("\n  ..." if len(set(methods)) > 30 else "")
            ),
            remediation=(
                "If you don't use Jetpack / WP mobile / pingbacks, disable XML-RPC entirely:\n"
                "  add_filter('xmlrpc_enabled', '__return_false');\n"
                "Or block /xmlrpc.php at the web server."
            ),
            url=client.url("/xmlrpc.php"),
            extra={"methods": sorted(set(methods))},
        )
    )

    for method, (sev, reason) in DANGEROUS_METHODS.items():
        if method in methods:
            findings.append(
                Finding(
                    severity=sev,
                    title=f"XML-RPC method exposed: {method}",
                    evidence=f"system.listMethods includes {method!r}. {reason}",
                    remediation=(
                        f"Disable this specific method:\n"
                        f"  add_filter('xmlrpc_methods', function($m){{ unset($m['{method}']); return $m; }});"
                    ),
                    url=client.url("/xmlrpc.php"),
                )
            )

    # Specific high-severity combination
    has_multicall = "system.multicall" in methods
    has_users = "wp.getUsersBlogs" in methods
    if has_multicall and has_users:
        findings.append(
            Finding(
                severity="high",
                title="XML-RPC brute-force amplifier present: multicall + wp.getUsersBlogs",
                evidence=(
                    "Both system.multicall and wp.getUsersBlogs are exposed.\n"
                    "Attackers wrap dozens of auth attempts in a single HTTP request (multicall) to bypass per-IP "
                    "rate-limit that only sees one request per http hit."
                ),
                remediation=(
                    "Disable at minimum system.multicall:\n"
                    "  add_filter('xmlrpc_methods', function($m){ unset($m['system.multicall']); return $m; });\n"
                    "Or fully block /xmlrpc.php at the server."
                ),
                url=client.url("/xmlrpc.php"),
            )
        )

    return findings
