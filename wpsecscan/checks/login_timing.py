"""Login timing side-channel — username enumeration via response timing.

WordPress's wp-login.php often returns DIFFERENT response times depending on
whether the username exists:
  - User exists, password wrong  → bcrypt hash comparison runs (~300+ ms)
  - User doesn't exist           → fast bail (~50-100 ms)

That delta lets an attacker prune their brute-force list to only valid users.

Probe: send 5 wrong-password attempts for `admin` (likely valid) and 5 for a
random synthetic username (definitely invalid). Compare medians. Flag ≥40%
delta as a username-enumeration vector.

Passive (no real password guesses, just timing).
"""
from __future__ import annotations

import secrets
import statistics
import time

from ..http import Client
from ..models import Finding

ATTEMPTS_PER_USER = 5
TIMING_DELTA_PCT = 40  # ≥40% slower for valid user = flag


async def _measure_login(client: Client, username: str, password: str) -> float | None:
    """One wrong-password login. Returns elapsed seconds, or None on transport error."""
    t0 = time.perf_counter()
    r = await client.post(
        "/wp-login.php",
        data={
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "testcookie": "1",
        },
        headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
    )
    if r is None:
        return None
    return time.perf_counter() - t0


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Pre-check: is wp-login.php reachable?
    step("checking wp-login.php reachability for timing probe...")
    pre = await client.get("/wp-login.php")
    if pre is None or pre.status_code != 200 or "user_login" not in (pre.text or ""):
        findings.append(
            Finding(
                severity="info",
                title="Login timing probe skipped: /wp-login.php not reachable",
                evidence=f"GET /wp-login.php -> {pre.status_code if pre else 'no response'}",
                remediation="No action.",
                url=client.url("/wp-login.php"),
            )
        )
        return findings

    bogus_user = "wpsec-noexist-" + secrets.token_hex(4)
    fixed_wrong_pw = "wpsec-timing-canary-wrong-pw-DO-NOT-VARY"

    valid_times: list[float] = []
    invalid_times: list[float] = []

    # Interleave attempts so server-side load fluctuations affect both sides equally.
    for i in range(ATTEMPTS_PER_USER):
        step(f"timing probe attempt {i + 1}/{ATTEMPTS_PER_USER} for admin...")
        t = await _measure_login(client, "admin", fixed_wrong_pw)
        if t is not None:
            valid_times.append(t)
        step(f"timing probe attempt {i + 1}/{ATTEMPTS_PER_USER} for synthetic non-existent user...")
        t = await _measure_login(client, bogus_user, fixed_wrong_pw)
        if t is not None:
            invalid_times.append(t)

    if len(valid_times) < 3 or len(invalid_times) < 3:
        findings.append(
            Finding(
                severity="info",
                title="Login timing probe inconclusive — too many network errors",
                evidence=f"Got {len(valid_times)} valid-user samples, {len(invalid_times)} invalid-user samples.",
                remediation="No action.",
                url=client.url("/wp-login.php"),
            )
        )
        return findings

    v_med = statistics.median(valid_times) * 1000  # ms
    i_med = statistics.median(invalid_times) * 1000
    delta_pct = ((v_med - i_med) / max(i_med, 1)) * 100

    sample_table = (
        f"  admin (likely-valid):  median {v_med:>6.1f} ms  ({len(valid_times)} samples)\n"
        f"  {bogus_user[:30]} (definitely-invalid):  median {i_med:>6.1f} ms  ({len(invalid_times)} samples)\n"
        f"  delta:  {delta_pct:+.1f}%"
    )

    if delta_pct >= TIMING_DELTA_PCT:
        findings.append(
            Finding(
                severity="medium",
                title=f"Login timing leak: valid user takes {delta_pct:.0f}% longer than invalid",
                evidence=(
                    f"{sample_table}\n\n"
                    "WordPress runs bcrypt comparison only for known usernames. The timing delta lets an "
                    "attacker enumerate which usernames exist on your site by measuring response time, even "
                    "with no error-message difference."
                ),
                remediation=(
                    "WP core mitigates this somewhat in recent versions; if you're on an older release, "
                    "upgrade. For belt-and-braces, install a plugin like 'Hide My WP Ghost' that adds a "
                    "constant-time pre-check, OR enable a WAF rule that adds 100-300 ms of jitter to all "
                    "wp-login.php POSTs (Cloudflare: Workers; Nginx: ngx_http_delay_module)."
                ),
                url=client.url("/wp-login.php"),
                extra={"valid_user_median_ms": round(v_med, 1),
                       "invalid_user_median_ms": round(i_med, 1),
                       "delta_pct": round(delta_pct, 1)},
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"No exploitable login timing leak ({delta_pct:+.0f}% delta within tolerance)",
                evidence=sample_table,
                remediation="No action — timing-based username enumeration not viable here.",
                url=client.url("/wp-login.php"),
            )
        )
    return findings
