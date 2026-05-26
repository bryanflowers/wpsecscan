"""Login-throttling defense test.

Sends 6 deliberately-wrong logins for a synthetic non-existent user.
If the site rate-limits / shows a captcha by attempt #6, throttling works.
If all 6 attempts return identical 'invalid credentials' pages, the site
isn't throttling.

This is NOT brute force: same wrong password each time, single fake user.
Never enumerates passwords.
"""
from __future__ import annotations

import asyncio
import secrets

from ..http import Client
from ..models import Finding

ATTEMPTS = 6
assert ATTEMPTS == 6, "login-throttle test must stay at exactly 6 attempts"

PACING_SECONDS = 2.0
WRONG_PASSWORD = "wpsecscan-canary-pw-XXXXX"

THROTTLE_MARKERS = (
    "too many",
    "try again later",
    "limit login",
    "wordfence",
    "rate limit",
    "challenge",
    "g-recaptcha",
    "recaptcha",
    "hcaptcha",
    "cloudflare",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Lockout-risk gate — same protection as default_creds. Sending 6 wrong
    # passwords in 12 seconds is well above Wordfence's default 5-fails-in-4-
    # minutes threshold and will permanently ban the scanner IP. Override with
    # `--ignore-lockout-risk` once your IP is allowlisted in the security plugin.
    waf_shared = ctx.get("shared", {}).get("waf") or []
    LOCKOUT_WAFS = {"Wordfence", "Sucuri", "Imperva (Incapsula)"}
    if not ctx.get("ignore_lockout_risk") and any(w in LOCKOUT_WAFS for w in waf_shared):
        blocking = [w for w in waf_shared if w in LOCKOUT_WAFS]
        findings.append(
            Finding(
                severity="info",
                title=f"Login-throttle test skipped — {', '.join(blocking)} can ban scanner IP",
                evidence=(
                    f"Detected: {', '.join(blocking)}. Sending {ATTEMPTS} wrong logins would trigger "
                    "their IP ban policy before the test could conclude."
                ),
                remediation=(
                    "Allowlist your scanner IP in the security plugin, then re-run with "
                    "--ignore-lockout-risk."
                ),
                url=client.url("/wp-login.php"),
            )
        )
        return findings

    # Pre-check
    step("checking /wp-login.php reachability before throttle test...")
    pre = await client.get("/wp-login.php")
    if pre is None or pre.status_code != 200 or "user_login" not in (pre.text or ""):
        findings.append(
            Finding(
                severity="info",
                title="Login-throttling test skipped: /wp-login.php not reachable",
                evidence=f"GET /wp-login.php -> {pre.status_code if pre else 'no response'}",
                remediation="No action needed.",
                url=client.url("/wp-login.php"),
            )
        )
        return findings

    canary_user = "wpsecscan-canary-" + secrets.token_hex(4)
    statuses: list[int] = []
    bodies: list[str] = []
    throttle_detected_at: int | None = None

    for i in range(ATTEMPTS):
        if i > 0:
            await asyncio.sleep(PACING_SECONDS)
        step(f"throttle test attempt {i+1}/{ATTEMPTS} (synthetic user '{canary_user}')...")
        r = await client.post(
            "/wp-login.php",
            data={
                "log": canary_user,
                "pwd": WRONG_PASSWORD,
                "wp-submit": "Log In",
                "testcookie": "1",
            },
            headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
        )
        if r is None:
            statuses.append(0)
            bodies.append("")
            continue
        statuses.append(r.status_code)
        body = (r.text or "")[:2000]
        bodies.append(body)
        if r.status_code in (429, 503):
            throttle_detected_at = i + 1
            break
        if any(m in body.lower() for m in THROTTLE_MARKERS):
            throttle_detected_at = i + 1
            break

    if throttle_detected_at:
        findings.append(
            Finding(
                severity="info",
                title=f"Login throttling kicked in at attempt #{throttle_detected_at} (defense works)",
                evidence=(
                    f"Sent {throttle_detected_at} wrong-password attempts for synthetic user '{canary_user}'. "
                    f"Attempt #{throttle_detected_at} returned a throttle response (HTTP {statuses[throttle_detected_at-1]}). "
                    "Brute-force is meaningfully harder against this site."
                ),
                remediation="No action needed — throttling is the defense working as intended.",
                url=client.url("/wp-login.php"),
            )
        )
    else:
        evidence_lines = [
            f"Sent {ATTEMPTS} wrong-password attempts for non-existent user '{canary_user}'.",
            f"Status codes: {statuses}",
            f"Body lengths: {[len(b) for b in bodies]}",
            "No 429/503, no captcha markers, no 'too many attempts' string.",
            "The site does not appear to rate-limit failed logins — vulnerable to online brute force.",
        ]
        findings.append(
            Finding(
                severity="medium",
                title="No login rate-limiting detected",
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Install a rate-limiting plugin (Wordfence, Limit Login Attempts Reloaded, iThemes Security). "
                    "At the server level, fail2ban with a wp-login.php pattern is also effective. "
                    "Enable 2FA on all administrator accounts for defense in depth."
                ),
                url=client.url("/wp-login.php"),
                extra={
                    "next_steps": [
                        "# Manually verify by repeating 10 wrong logins for a single bad user:",
                        "# for i in {1..10}; do curl -s -X POST <target>/wp-login.php -d 'log=fakeuser&pwd=wrong&wp-submit=Log+In' -o /dev/null -w '%{http_code}\\n'; done",
                    ],
                },
            )
        )
    return findings
