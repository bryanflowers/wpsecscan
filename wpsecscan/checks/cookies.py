"""Cookie hardening check — inspect Set-Cookie flags on common WP endpoints.

Looks specifically at /wp-login.php and /wp-admin/ (which set wp-* cookies on
login attempts) for missing Secure / HttpOnly / SameSite flags.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Cookies that should be Secure + HttpOnly (and ideally SameSite=Lax or Strict)
WP_SENSITIVE_COOKIE_PREFIXES = (
    "wordpress_logged_in_",
    "wordpress_sec_",
    "wp-settings-",
    "wordpress_test_cookie",
    "PHPSESSID",
)


def _parse_set_cookies(raw: str) -> list[dict]:
    """Parse multi-cookie Set-Cookie header into individual cookie dicts."""
    out: list[dict] = []
    if not raw:
        return out
    # Split on comma — but only when followed by a cookie-name=value (avoid commas inside Expires)
    parts = re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw)
    for part in parts:
        sub = [a.strip() for a in part.split(";")]
        if not sub or "=" not in sub[0]:
            continue
        name, _, value = sub[0].partition("=")
        attrs = {"name": name.strip(), "value": value.strip(), "secure": False, "httponly": False, "samesite": ""}
        for a in sub[1:]:
            la = a.lower()
            if la == "secure":
                attrs["secure"] = True
            elif la == "httponly":
                attrs["httponly"] = True
            elif la.startswith("samesite="):
                attrs["samesite"] = a.split("=", 1)[1].strip()
        out.append(attrs)
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    targets = ("/wp-login.php", "/wp-admin/", "/")
    all_cookies: list[tuple[str, dict]] = []
    for path in targets:
        step(f"fetching {path} and inspecting Set-Cookie...")
        r = await client.get(path)
        if r is None:
            continue
        # httpx may concatenate or split multi-valued headers depending on origin.
        # get_list() returns all Set-Cookie values; fall back to single value if the
        # backing implementation doesn't expose get_list (e.g. test FakeResponse).
        if hasattr(r.headers, "get_list"):
            cookie_lines = r.headers.get_list("set-cookie") or []
        else:
            single = r.headers.get("set-cookie", "")
            cookie_lines = [single] if single else []
        for raw in cookie_lines:
            for c in _parse_set_cookies(raw):
                all_cookies.append((path, c))

    if not all_cookies:
        findings.append(
            Finding(
                severity="info",
                title="No cookies observed from probed endpoints",
                evidence="GET /wp-login.php, /wp-admin/, and / returned no Set-Cookie headers.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    insecure: list[tuple[str, dict, list[str]]] = []
    for path, c in all_cookies:
        problems: list[str] = []
        sensitive = any(c["name"].startswith(p) for p in WP_SENSITIVE_COOKIE_PREFIXES) or c["name"] == "PHPSESSID"
        if not c["secure"]:
            problems.append("missing Secure")
        if not c["httponly"] and sensitive:
            problems.append("missing HttpOnly")
        if not c["samesite"]:
            problems.append("missing SameSite")
        if problems:
            insecure.append((path, c, problems))

    if insecure:
        lines = []
        for path, c, probs in insecure[:15]:
            lines.append(f"  [{path}] {c['name']}: {', '.join(probs)}")
        sev = "medium" if any(c["name"].startswith("wordpress_logged_in_") for _, c, _ in insecure) else "low"
        findings.append(
            Finding(
                severity=sev,
                title=f"{len(insecure)} cookie(s) missing security flags",
                evidence="\n".join(lines),
                remediation=(
                    "Set Secure (HTTPS-only), HttpOnly (no JS access), and SameSite=Lax/Strict (CSRF mitigation). "
                    "For WP cookies, in wp-config.php: define('COOKIE_DOMAIN', 'example.com'); "
                    "define('FORCE_SSL_ADMIN', true); At the server level (Nginx) you can also rewrite Set-Cookie headers."
                ),
                url=ctx["target"],
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title="All observed cookies have appropriate security flags",
                evidence=f"Inspected {len(all_cookies)} cookie(s); none missing required flags.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
