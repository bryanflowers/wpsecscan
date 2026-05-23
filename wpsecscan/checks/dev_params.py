"""Beta / test / debug parameter discovery.

Probes common 'unlock-the-hidden-feature' query parameters against the homepage.
A response that DIFFERS from the baseline indicates the parameter is consumed
somewhere in the code path — often by a forgotten debug toggle.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (param, value, what-it-typically-unlocks)
DEV_PARAMS = (
    ("debug", "1", "WP_DEBUG-style debug output"),
    ("test", "1", "test/preview mode"),
    ("staging", "1", "staging-mode bypass"),
    ("preview", "1", "draft preview without auth"),
    ("draft", "1", "draft post visibility"),
    ("dev", "1", "developer mode toggle"),
    ("_pjax", "1", "PJAX partial render"),
    ("nocache", "1", "cache bypass"),
    ("force_reload", "1", "cache invalidation"),
    ("admin", "1", "admin-view toggle (rare but seen)"),
    ("logged_in", "1", "auth-bypass test"),
    ("verbose", "1", "verbose error output"),
    ("trace", "1", "stack-trace exposure"),
    ("XDEBUG_SESSION_START", "wpsec", "PHP Xdebug session trigger"),
)

BODY_DELTA_THRESHOLD = 500  # bytes


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("baselining / for dev-param comparison...")
    baseline = await client.get("/")
    if baseline is None or not baseline.content:
        findings.append(
            Finding(
                severity="info",
                title="Dev-parameter probe skipped — couldn't baseline /",
                evidence="GET / returned no body.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings
    base_len = len(baseline.content or b"")
    base_status = baseline.status_code

    deltas: list[tuple[str, str, str, int, int]] = []
    for param, value, label in DEV_PARAMS:
        step(f"probing ?{param}={value}...")
        r = await client.get("/", params={param: value})
        if r is None:
            continue
        delta = abs(len(r.content or b"") - base_len)
        # Indicators that the parameter changed something:
        # - status code differs (e.g. 200 -> 302 redirect-to-debug)
        # - body length differs by > threshold
        # - response contains "debug" / "trace" / "warning" markers absent from baseline
        body_lc = (r.text or "")[:5000].lower()
        baseline_lc = (baseline.text or "")[:5000].lower()
        new_markers = [m for m in ("warning:", "notice:", "stack trace", "xdebug", "fatal error",
                                    "deprecated:", "<!-- debug", "debug=true")
                        if m in body_lc and m not in baseline_lc]
        if r.status_code != base_status or delta > BODY_DELTA_THRESHOLD or new_markers:
            deltas.append((param, value, label, r.status_code, delta))

    if not deltas:
        findings.append(
            Finding(
                severity="info",
                title="No dev/test parameters consumed by the homepage",
                evidence=f"Probed {len(DEV_PARAMS)} common dev toggles; none altered the response.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for param, value, label, status, delta in deltas:
        sev = "medium" if any(k in label for k in ("debug", "trace", "Xdebug", "admin", "auth")) else "low"
        findings.append(
            Finding(
                severity=sev,
                title=f"Dev/test parameter consumed: ?{param}={value} ({label})",
                evidence=(
                    f"GET /?{param}={value} -> HTTP {status} (body delta {delta} bytes vs baseline). "
                    f"Suspect: {label}."
                ),
                remediation=(
                    "Audit the plugin/theme that handles this parameter — production code shouldn't have "
                    "an unauthenticated debug toggle. If it's WP_DEBUG bleeding into responses, set "
                    "`define('WP_DEBUG_DISPLAY', false);` in wp-config.php."
                ),
                url=client.url(f"/?{param}={value}"),
            )
        )
    return findings
