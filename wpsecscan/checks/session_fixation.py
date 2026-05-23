"""H4 Session-fixation chain.

Pattern: an attacker sets a session cookie on the victim BEFORE login.
A vulnerable application re-uses that cookie value after authentication,
letting the attacker — who already knows the cookie — hijack the session.

We can't fully test fixation without admin credentials, but we CAN detect
the precondition: does the server accept arbitrary client-set values for
the cookies it later treats as session identifiers? If yes AND the cookies
are flagged HttpOnly+Secure+SameSite=Strict, fixation requires user-side
XSS. If NO HttpOnly / loose SameSite, fixation is trivial.

This is a derivative finding from the existing cookie check, so we keep it
narrow: pre-set a synthetic value, hit /wp-login.php, verify the server
either:
  (a) ignores our value and issues a fresh cookie (good — no fixation),
  (b) echoes our value back (bad — fixation likely possible).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

SESSION_COOKIE_NAMES = (
    "wordpress_test_cookie",
    "wp-settings-1",
    "PHPSESSID",
    "wordpress_logged_in_",  # prefix
)
SYNTHETIC_VALUE = "wpsec_fixation_probe_123abc"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("session-fixation: pre-setting synthetic cookies...")
    cookies = {n: SYNTHETIC_VALUE for n in SESSION_COOKIE_NAMES if not n.endswith("_")}

    # Use the cookie= kwarg so httpx attaches them; if the underlying Client
    # doesn't support per-request cookies, set them via a Cookie header.
    cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookies.items())
    r = await client.get("/wp-login.php", headers={"Cookie": cookie_hdr})
    if r is None:
        findings.append(Finding(
            severity="info",
            title="Session-fixation probe — /wp-login.php unreachable",
            evidence="Couldn't reach the login page.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Inspect Set-Cookie in response. If the server returns the same name with a
    # DIFFERENT value, it's regenerating — good. If absent, it accepted our value.
    set_cookies = []
    if hasattr(r.headers, "get_list"):
        set_cookies = r.headers.get_list("set-cookie")
    elif r.headers.get("set-cookie"):
        set_cookies = [r.headers["set-cookie"]]

    accepted_names: list[str] = []
    regenerated_names: list[str] = []
    for name in cookies:
        regen = False
        for sc in set_cookies:
            if sc.lower().startswith(name.lower() + "="):
                # Extract the value the server is sending
                val = sc.split("=", 1)[1].split(";", 1)[0]
                if val != SYNTHETIC_VALUE:
                    regenerated_names.append(name)
                    regen = True
                    break
        if not regen:
            accepted_names.append(name)

    if accepted_names and not regenerated_names:
        findings.append(Finding(
            severity="medium",
            title=f"Session-fixation precondition: server accepted {len(accepted_names)} client-set cookie(s) without regenerating",
            evidence=(
                f"Pre-set the following cookies and hit /wp-login.php:\n  "
                + "\n  ".join(f"- {n}" for n in accepted_names)
                + "\n\nNo Set-Cookie response regenerated them with a different value. If the server uses "
                "these cookies as the session identifier post-login, an attacker who can plant a cookie "
                "in the victim's browser (subdomain XSS, MITM, etc.) can fixate the session."
            ),
            remediation=(
                "WordPress should regenerate `wordpress_logged_in_*` on successful login. If you've added a "
                "custom session plugin, ensure it calls `session_regenerate_id(true)` (PHP) on login. "
                "Belt-and-braces: set every session cookie HttpOnly + Secure + SameSite=Strict."
            ),
            url=ctx["target"] + "/wp-login.php",
        ))
    elif regenerated_names:
        findings.append(Finding(
            severity="info",
            title=f"Session cookies regenerated on /wp-login.php ({len(regenerated_names)} cookie(s))",
            evidence=f"Server actively reset the cookies we pre-planted: {', '.join(regenerated_names)}. Session-fixation unlikely.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
