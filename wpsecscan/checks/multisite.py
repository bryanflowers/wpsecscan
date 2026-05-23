"""WordPress Multisite audit.

Multisite (Network) installations have extra attack surface: the network admin,
signup forms, sunrise.php drop-in, and per-site subdirectory/subdomain access.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (path, what-it-indicates, severity-if-200)
MULTISITE_PROBES = (
    ("/wp-signup.php",                    "Multisite open signup form — invites spam admin creation",  "medium"),
    ("/wp-activate.php",                  "Multisite activation endpoint",                              "low"),
    ("/wp-admin/network/",                "Network admin reachable (should be redirect-to-login)",      "info"),
    ("/wp-admin/network/index.php",       "Network admin dashboard URL",                                "info"),
    ("/wp-admin/network/site-new.php",    "Site-new page in network admin",                             "info"),
    ("/wp-admin/network/users.php",       "Network user list page",                                     "info"),
    ("/wp-admin/network/settings.php",    "Network settings page",                                      "info"),
    ("/wp-content/sunrise.php",           "sunrise.php drop-in (legit for multisite domain mapping; verify content)", "low"),
    ("/wp-content/mu-plugins/",           "Must-use plugins directory listing",                         "low"),
    # Some multisite installs use blogs.dir for old uploads
    ("/wp-content/blogs.dir/",            "Legacy blogs.dir directory listing (pre-3.5 multisite)",     "low"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    is_multisite = False
    hits: list[dict] = []
    for path, label, sev in MULTISITE_PROBES:
        step(f"probing {path}...")
        r = await client.get(path, follow_redirects=False)
        if r is None:
            continue
        # 200 or 302 to login both signal "the page exists and is reachable"
        if r.status_code in (200, 302):
            body = r.text or ""
            # Distinguish "real multisite endpoint" from "WP returns the homepage for any path"
            looks_real = False
            if path == "/wp-signup.php" and ("Get your own" in body or "signup-blogname" in body or "signup_form" in body):
                looks_real = True
                is_multisite = True
            elif path == "/wp-activate.php" and ("activation key" in body.lower() or "activate.php" in body.lower()):
                looks_real = True
                is_multisite = True
            elif "/wp-admin/network/" in path and (r.status_code == 302 and "wp-login" in r.headers.get("location", "")):
                looks_real = True
                is_multisite = True
            elif "<title>Index of" in body and path.endswith("/"):
                looks_real = True
            elif r.status_code == 200 and len(body) < 5000:
                # Short 200 bodies are usually real endpoints (not soft-404 homepage rewrites)
                looks_real = True

            if looks_real:
                hits.append({"path": path, "label": label, "severity": sev, "status": r.status_code})

    if is_multisite:
        findings.append(
            Finding(
                severity="info",
                title="WordPress Multisite (Network) installation detected",
                evidence=(
                    "Probes for /wp-signup.php, /wp-activate.php, or /wp-admin/network/ returned multisite-shaped responses. "
                    "Multisite installs have additional admin surface (the Network Admin) and per-site subdomain/subdir handling."
                ),
                remediation=(
                    "If multisite is intentional: lock down the network admin to admin IPs, disable open signups unless needed, "
                    "and audit sunrise.php for legit content. If multisite is NOT intentional, you've found a real misconfig."
                ),
                url=client.url("/wp-admin/network/"),
            )
        )

    for h in hits:
        # Avoid duplicating the info finding above for /wp-signup, /wp-activate
        if h["path"] in ("/wp-signup.php", "/wp-activate.php") or "/wp-admin/network" in h["path"]:
            findings.append(
                Finding(
                    severity=h["severity"],
                    title=f"Multisite endpoint reachable: {h['path']}",
                    evidence=f"GET {h['path']} -> HTTP {h['status']}\n  {h['label']}",
                    remediation=(
                        f"If this site doesn't need {h['path']}, block it at the server. "
                        "For open signups specifically: Network Admin → Settings → Allow new registrations → Disabled."
                    ),
                    url=client.url(h["path"]),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="Not a Multisite installation (no multisite endpoints detected)",
                evidence=f"Probed {len(MULTISITE_PROBES)} known multisite paths; none returned multisite-shaped responses.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
