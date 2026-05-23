from __future__ import annotations

from ..http import Client
from ..models import Finding

XMLRPC_BODY = (
    "<?xml version=\"1.0\"?>\n"
    "<methodCall><methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # wp-login.php reachable?
    step("probing /wp-login.php...")
    lg = await client.get("/wp-login.php")
    if lg is not None and lg.status_code == 200 and "user_login" in (lg.text or ""):
        findings.append(
            Finding(
                severity="info",
                title="Default login page /wp-login.php is reachable",
                evidence="GET /wp-login.php → 200, looks like the WP login form.",
                remediation=(
                    "Consider moving the admin URL with a plugin (e.g. WPS Hide Login) "
                    "and add IP allow-listing or 2FA. The default path is the #1 brute-force target."
                ),
                url=client.url("/wp-login.php"),
            )
        )

    # wp-admin reachable?
    step("probing /wp-admin/...")
    ad = await client.get("/wp-admin/", follow_redirects=False)
    if ad is not None and ad.status_code in (200, 301, 302):
        findings.append(
            Finding(
                severity="info",
                title="/wp-admin/ reachable",
                evidence=f"GET /wp-admin/ → {ad.status_code}",
                remediation="Same as wp-login.php — restrict by IP/2FA or rename the admin path.",
                url=client.url("/wp-admin/"),
            )
        )

    # XML-RPC enabled?
    step("checking XML-RPC via system.listMethods...")
    xr = await client.post("/xmlrpc.php", content=XMLRPC_BODY, headers={"Content-Type": "text/xml"})
    if xr is not None and xr.status_code == 200 and "methodResponse" in (xr.text or ""):
        methods = "wp.getUsersBlogs" in xr.text or "system.multicall" in xr.text
        findings.append(
            Finding(
                severity="medium" if methods else "low",
                title="XML-RPC endpoint is enabled",
                evidence=f"POST /xmlrpc.php system.listMethods → 200 with valid methodResponse. "
                f"{'system.multicall + wp.getUsersBlogs available — amplification + brute-force vector.' if methods else ''}",
                remediation=(
                    "If you don't use Jetpack or the WP mobile app, disable XML-RPC. "
                    "Block /xmlrpc.php at the server (Nginx: `location = /xmlrpc.php { deny all; }`). "
                    "If you need it, restrict by IP and disable system.multicall via the "
                    "`xmlrpc_methods` filter to neutralize the brute-force amplifier."
                ),
                url=client.url("/xmlrpc.php"),
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Login surface appears hardened",
                evidence="/wp-login.php and /wp-admin/ not reachable as default; XML-RPC not responding.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
