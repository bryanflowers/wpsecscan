"""Default-credentials probe — strictly capped at 10 attempts against
well-known *shipped* defaults from plugin/theme install guides.

This is NOT brute force. It tests one specific question: "did anyone leave
the install-wizard's default credentials in place?" The list never grows
beyond 10; module-load asserts that bound. Each attempt is paced 3s apart;
if the site throttles, we abort.

Opt-in via aggressive mode only.
"""
from __future__ import annotations

import asyncio
import re

from ..http import Client
from ..models import Finding

# Documented shipped defaults — these come from plugin install guides,
# demo sites, and CTF / homelab WP setups. They are NOT user-guessing
# attempts; they're a "did you finish setup?" check.
DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("admin",   "admin"),
    ("admin",   "password"),
    ("admin",   "admin123"),
    ("admin",   "changeme"),
    ("demo",    "demo"),
    ("demo",    "demo123"),
    ("test",    "test"),
    ("wp",      "wp"),
    ("root",    "root"),
    ("support", "support"),
)
assert len(DEFAULT_CREDENTIALS) <= 10, "default-creds list must stay ≤ 10 entries"

# Sleep between attempts (seconds). Tuned to be slow enough that we
# don't trip default WP rate limits on a healthy install.
PACING_SECONDS = 3.0

ADMIN_BAR_RE = re.compile(r'<div\s+id=["\']wpadminbar["\']', re.IGNORECASE)
LOGIN_FORM_RE = re.compile(r'name=["\']log["\']', re.IGNORECASE)
THROTTLE_MARKERS = (
    "too many",
    "try again later",
    "limit login",
    "wordfence",
    "rate limit",
    "challenge",
)


async def _attempt_login(client: Client, user: str, pwd: str) -> tuple[bool, int, str]:
    """One POST to /wp-login.php. Returns (succeeded, status_code, body_snippet)."""
    r = await client.post(
        "/wp-login.php",
        data={
            "log": user,
            "pwd": pwd,
            "wp-submit": "Log In",
            "testcookie": "1",
        },
        headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
    )
    if r is None:
        return False, 0, ""
    body = r.text or ""
    # Success heuristics: admin bar present, redirect to wp-admin, or no login form
    if ADMIN_BAR_RE.search(body):
        return True, r.status_code, body[:200]
    if r.status_code in (301, 302):
        loc = r.headers.get("location", "")
        if "/wp-admin" in loc and "wp-login" not in loc:
            return True, r.status_code, f"redirect to {loc}"
    if r.status_code == 200 and not LOGIN_FORM_RE.search(body):
        # 200 with no login form is unusual — could be success-without-redirect
        return True, r.status_code, body[:200]
    return False, r.status_code, body[:300]


def _looks_throttled(status_code: int, body: str) -> bool:
    if status_code in (429, 503):
        return True
    body_lower = (body or "").lower()
    return any(m in body_lower for m in THROTTLE_MARKERS)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Pre-check: is /wp-login.php even reachable? If not, skip cleanly.
    step("checking /wp-login.php reachability before any auth attempts...")
    pre = await client.get("/wp-login.php")
    if pre is None or pre.status_code != 200 or "user_login" not in (pre.text or ""):
        findings.append(
            Finding(
                severity="info",
                title="Default-credentials probe skipped: /wp-login.php not reachable",
                evidence=(
                    f"GET /wp-login.php -> {pre.status_code if pre else 'no response'}; "
                    "this site likely uses a moved-login plugin or blocks /wp-login.php at the WAF."
                ),
                remediation="No action needed.",
                url=client.url("/wp-login.php"),
            )
        )
        return findings

    attempted = 0
    aborted = False
    for user, pwd in DEFAULT_CREDENTIALS:
        if attempted >= 10:  # belt-and-suspenders for the assertion above
            break
        if attempted > 0:
            await asyncio.sleep(PACING_SECONDS)
        step(f"trying default credential pair: {user} / {'*'*len(pwd)}")
        attempted += 1
        ok, status, snippet = await _attempt_login(client, user, pwd)
        if ok:
            findings.append(
                Finding(
                    severity="critical",
                    title=f"Default credentials accepted: {user} / {pwd}",
                    evidence=(
                        f"POST /wp-login.php with log={user} pwd={pwd} -> HTTP {status}\n"
                        f"  {snippet}\n"
                        "This is one of the documented install-defaults — change the password immediately."
                    ),
                    remediation=(
                        f"Log in as '{user}' and change the password right now. "
                        "Audit the account's recent activity (Tools → Site Health, plus any audit-log plugin). "
                        "Rotate ALL administrator passwords and force a session refresh "
                        "(plugins like 'WP Logout Everyone' help). Consider 2FA going forward."
                    ),
                    url=client.url("/wp-login.php"),
                    extra={
                        "username": user,
                        "next_steps": [
                            "# Log in immediately and rotate this password:",
                            f"# {client.url('/wp-login.php')}",
                        ],
                    },
                )
            )
            return findings  # stop on first success — no need to try more
        if _looks_throttled(status, snippet):
            aborted = True
            findings.append(
                Finding(
                    severity="info",
                    title=f"Default-creds probe aborted after {attempted} attempt(s) — throttling kicked in",
                    evidence=(
                        f"Attempt #{attempted} (user={user}) returned HTTP {status} with throttle markers in body. "
                        "This is good for security — but it also means we can't finish the probe. "
                        "If you want full coverage, whitelist your scanner IP at the WAF and re-run."
                    ),
                    remediation="No action needed — the throttling itself is the defense working.",
                    url=client.url("/wp-login.php"),
                )
            )
            return findings

    if not aborted:
        findings.append(
            Finding(
                severity="info",
                title=f"All {attempted} known default credentials were rejected",
                evidence=(
                    f"Tried {attempted} documented install-default credential pairs (admin/admin, demo/demo, etc.). "
                    "None succeeded. Note this is a tiny set — passwords could still be weak in ways this check doesn't see. "
                    "For a real password audit, dump wp_users and run hashcat locally."
                ),
                remediation="No action needed for this check. Consider an offline password audit (`hashcat -m 400 wp_users.txt rockyou.txt`).",
                url=client.url("/wp-login.php"),
            )
        )
    return findings
