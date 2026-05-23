"""Deep login-throttle mapper.

Sends N deliberately-wrong logins for a single synthetic non-existent user
(one attempt every `pacing` seconds — default 10, range 5-60). Records when
the response shape changes —
status code goes 4xx/5xx, body length jumps, captcha markers appear — and
reports the threshold ("locks out at attempt 14, ~3 min in") or confirms no
threshold up to the cap.

NOT brute force. The username is synthetic (random nonce, cannot exist),
the password is a fixed wrong-value constant — we *never* vary it across
attempts. The goal is to map the defense, not log in.

This check is opt-in only. Enable via:
  - CLI:  --deep-throttle  (and optionally --deep-throttle-attempts N
                              and --deep-throttle-pacing SECONDS)
  - GUI:  the "Deep throttle mapping" checkbox + the attempts spinbox
"""
from __future__ import annotations

import asyncio
import secrets
import time

from ..http import Client
from ..models import Finding

DEFAULT_ATTEMPTS = 120
MIN_ATTEMPTS = 10
MAX_ATTEMPTS = 500  # hard cap — even 500 × 5s = ~42 min, anything more is wasteful

DEFAULT_PACING_SECONDS = 10.0
MIN_PACING_SECONDS = 5.0   # below 5s tends to trip network-layer fail2ban before HTTP throttle
MAX_PACING_SECONDS = 60.0

WRONG_PASSWORD = "wpsecscan-deep-canary-fixed-wrong-password-DO-NOT-VARY"


def _clamp_attempts(n) -> int:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return DEFAULT_ATTEMPTS
    return max(MIN_ATTEMPTS, min(MAX_ATTEMPTS, n))


def _clamp_pacing(s) -> float:
    try:
        s = float(s)
    except (TypeError, ValueError):
        return DEFAULT_PACING_SECONDS
    return max(MIN_PACING_SECONDS, min(MAX_PACING_SECONDS, s))

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
    "blocked",
    "temporarily disabled",
    "locked",
)


def _is_throttled(status_code: int, body: str, baseline_body_len: int | None) -> tuple[bool, str]:
    """Heuristics for 'response looks like throttling'. Returns (yes, reason)."""
    if status_code in (429, 503):
        return True, f"HTTP {status_code}"
    body_lower = (body or "").lower()
    for m in THROTTLE_MARKERS:
        if m in body_lower:
            return True, f"body contains {m!r}"
    if baseline_body_len is not None and body:
        delta = abs(len(body) - baseline_body_len) / max(baseline_body_len, 1)
        if delta >= 0.40:
            return True, f"body length jumped {delta:.0%} from baseline"
    return False, ""


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    attempts = _clamp_attempts(ctx.get("deep_throttle_attempts", DEFAULT_ATTEMPTS))
    pacing = _clamp_pacing(ctx.get("deep_throttle_pacing_s", DEFAULT_PACING_SECONDS))
    est_minutes = (attempts * pacing) / 60.0

    if not ctx.get("deep_throttle"):
        findings.append(
            Finding(
                severity="info",
                title="Deep throttle mapping skipped (opt-in)",
                evidence=(
                    f"Pass --deep-throttle on the CLI, or tick the GUI checkbox, to run this defense map.\n"
                    f"Current settings would run {attempts} attempts at {pacing:.0f}s pacing (~{est_minutes:.0f} min)."
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    step("checking /wp-login.php reachability before deep throttle test...")
    pre = await client.get("/wp-login.php")
    if pre is None or pre.status_code != 200 or "user_login" not in (pre.text or ""):
        findings.append(
            Finding(
                severity="info",
                title="Deep throttle mapping skipped: /wp-login.php not reachable",
                evidence=f"GET /wp-login.php -> {pre.status_code if pre else 'no response'}",
                remediation="No action needed.",
                url=client.url("/wp-login.php"),
            )
        )
        return findings

    canary_user = "wpsecscan-deep-" + secrets.token_hex(4)
    started = time.perf_counter()
    samples: list[tuple[int, float, int, int, str]] = []  # (i, elapsed_s, status, body_len, signal)
    baseline_body_len: int | None = None
    threshold_at: int | None = None
    threshold_reason: str = ""
    # #14: cancel mid-throttle gracefully — read the same ctx slot the scanner uses.
    is_cancelled = ctx.get("is_cancelled") or (lambda: False)
    cancelled_at: int | None = None

    for i in range(attempts):
        if is_cancelled():
            cancelled_at = i
            break
        if i > 0:
            await asyncio.sleep(pacing)
        if is_cancelled():
            cancelled_at = i
            break
        elapsed = time.perf_counter() - started
        step(f"deep throttle attempt {i+1}/{attempts} at t+{elapsed:.0f}s (synthetic user '{canary_user}')...")
        r = await client.post(
            "/wp-login.php",
            data={
                "log": canary_user,
                "pwd": WRONG_PASSWORD,  # same string every attempt — never varies
                "wp-submit": "Log In",
                "testcookie": "1",
            },
            headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
        )
        if r is None:
            samples.append((i + 1, elapsed, 0, 0, "no response"))
            continue
        body = (r.text or "")
        body_len = len(body)
        if baseline_body_len is None and r.status_code == 200:
            baseline_body_len = body_len  # establish baseline from first 200 response
        throttled, reason = _is_throttled(r.status_code, body, baseline_body_len)
        signal = reason if throttled else "normal"
        samples.append((i + 1, elapsed, r.status_code, body_len, signal))
        if throttled and threshold_at is None:
            threshold_at = i + 1
            threshold_reason = reason
            # Stop early — we have our answer, no point pushing further and tripping
            # site-level abuse detection harder.
            break

    total_elapsed = time.perf_counter() - started
    table = "\n".join(
        f"  #{i:>2}  t+{e:>5.1f}s  HTTP {s}  {bl} bytes  {sig}"
        for (i, e, s, bl, sig) in samples
    )

    # #14: partial-result finding when cancelled mid-run, so the user keeps what we learned.
    if cancelled_at is not None and threshold_at is None:
        sev = "low" if samples else "info"
        title = (
            f"Deep throttle CANCELLED after {len(samples)}/{attempts} attempts "
            f"({total_elapsed:.0f}s) — partial result"
        )
        if samples:
            evidence = (
                f"Synthetic canary user: {canary_user}\n"
                f"Fixed wrong password used every attempt.\n"
                f"Cancelled at attempt #{cancelled_at + 1} (you clicked Cancel).\n\n"
                f"What we learned before cancel:\n{table}\n\n"
                f"No throttle threshold was hit in the attempts that completed."
            )
        else:
            evidence = "No attempts completed before cancel."
        findings.append(
            Finding(
                severity=sev,
                title=title,
                evidence=evidence,
                remediation=(
                    "Partial result only — re-run with --deep-throttle and let it finish for a full picture, "
                    "or with a smaller attempts count via --deep-throttle-attempts."
                ),
                url=client.url("/wp-login.php"),
                extra={"cancelled_at_attempt": cancelled_at + 1, "samples": len(samples)},
            )
        )
        return findings

    if threshold_at is not None:
        findings.append(
            Finding(
                severity="info",
                title=(
                    f"Login throttle threshold detected at attempt #{threshold_at}, "
                    f"~{samples[threshold_at - 1][1]:.0f}s into the test"
                ),
                evidence=(
                    f"Synthetic canary user: {canary_user}\n"
                    f"Fixed wrong password used every attempt (never varied).\n"
                    f"Throttle reason: {threshold_reason}\n\n"
                    f"Attempts:\n{table}\n\n"
                    f"Total elapsed: {total_elapsed:.1f}s before throttle kicked in.\n"
                    "This is the visible HTTP-layer defense. Network-layer (fail2ban, hosting "
                    "provider) defenses may activate at different thresholds and can't be measured this way."
                ),
                remediation="No action needed — throttling is the defense working.",
                url=client.url("/wp-login.php"),
                extra={"threshold_attempt": threshold_at, "threshold_elapsed_s": samples[threshold_at - 1][1]},
            )
        )
    else:
        # all attempts exhausted with no visible throttle
        findings.append(
            Finding(
                severity="high",
                title=f"No login throttling detected after {attempts} wrong-password attempts over {total_elapsed:.0f}s",
                evidence=(
                    f"Synthetic canary user: {canary_user}\n"
                    f"Fixed wrong password used every attempt.\n\n"
                    f"All {attempts} attempts:\n{table}\n\n"
                    "No 429/503, no captcha markers, no body-length anomalies. "
                    "An online brute-force attack is feasible against this login surface."
                ),
                remediation=(
                    "Install a login-throttling plugin (Wordfence Login Security, Limit Login Attempts Reloaded, "
                    "iThemes Security). Add fail2ban with a wp-login.php pattern at the server level. "
                    "Force 2FA on every administrator account.\n\n"
                    "Once the plugin is configured, re-run this check to verify the threshold."
                ),
                url=client.url("/wp-login.php"),
                extra={
                    "next_steps": [
                        "# Verify your hashes aren't weak (the real follow-up to no rate-limiting):",
                        "wpsecscan --password-audit wp_users.csv",
                        "# Install rate-limiting:",
                        "wp plugin install limit-login-attempts-reloaded --activate",
                    ],
                },
            )
        )

    return findings
