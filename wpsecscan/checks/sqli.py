"""Boolean / error / time-based SQL injection probes on common WP parameters.

Read-only payloads only — no DROP, INSERT, UPDATE, or destructive operators.
Detection is via:
  - SQL error fingerprints in response body
  - Differential response length between truthy ('1=1') vs falsy ('1=2') payloads
  - Time delta between baseline and SLEEP() payload (time-based blind)

Payloads are passed as raw strings via httpx `params=` so the HTTP client handles
percent-encoding once and correctly. (An earlier version pre-encoded payloads, which
httpx then percent-encoded again, corrupting the SQL fragment server-side.)
"""
from __future__ import annotations

import time

from ..baseline import calibrate
from ..http import Client
from ..models import Finding
from ..prove import build_replay_curl

# SQL error fingerprints (MySQL / MariaDB — WordPress's backend)
ERROR_SIGNATURES = (
    "You have an error in your SQL syntax",
    "supplied argument is not a valid MySQL",
    "mysql_fetch_array()",
    "mysqli_fetch_array()",
    "mysqli_num_rows()",
    "MySQLSyntaxErrorException",
    "Warning: mysql_",
    "Warning: mysqli_",
    "WordPress database error",
    "SQLSTATE[",
    "Unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "PDOException",
)

# (param_name, baseline_value, description)
TARGETS = (
    ("p",        "1",    "homepage post-id ?p="),
    ("cat",      "1",    "category ?cat="),
    ("author",   "1",    "author archive ?author="),
    ("page_id",  "2",    "page ?page_id="),
    ("s",        "test", "search ?s="),
)

# Raw payloads — httpx encodes once.
QUOTE  = "'"
TRUTHY = " AND 1=1-- -"
FALSY  = " AND 1=2-- -"


def _has_error(body: str | None) -> str | None:
    if not body:
        return None
    body_lower = body.lower()
    for sig in ERROR_SIGNATURES:
        if sig.lower() in body_lower:
            return sig
    return None


async def _probe_error(client: Client, param: str, baseline: str, desc: str) -> Finding | None:
    r = await client.get("/", params={param: baseline + QUOTE})
    if r is None:
        return None
    sig = _has_error(r.text)
    if sig:
        url = client.url(f"/?{param}={baseline}{QUOTE}")
        replay = build_replay_curl("GET", client.url("/"), params={param: baseline + QUOTE})
        return Finding(
            severity="critical",
            title=f"SQL error reflected from {desc}",
            evidence=(
                f"GET /?{param}={baseline}{QUOTE} -> {r.status_code}\n"
                f"  Response contains MySQL error signature: '{sig}'\n"
                "This typically indicates a parameter is being concatenated into a query unsafely."
            ),
            remediation=(
                "Find the plugin/theme handling this parameter and switch all DB access to "
                "prepared statements via $wpdb->prepare(). Validate and cast inputs (intval() for IDs). "
                "If it's a third-party plugin, update or remove it."
            ),
            url=url,
            extra={
                "provable": True,
                "prover": "sqli",
                "param": param,
                "vector": "error",
                "baseline_path": "/",
                "baseline_value": baseline,
                "replay": replay,
                "next_steps": [
                    f'sqlmap -u "{url}" --batch --risk=1 --level=2',
                ],
            },
        )
    return None


async def _probe_boolean(client: Client, param: str, baseline: str, desc: str, noise_floor: float) -> Finding | None:
    base = await client.get("/", params={param: baseline})
    t = await client.get("/", params={param: baseline + QUOTE + TRUTHY})
    f = await client.get("/", params={param: baseline + QUOTE + FALSY})
    if not all((base, t, f)):
        return None
    if base.status_code != 200 or t.status_code != 200:
        return None

    bb = len(base.content or b"")
    bt = len(t.content or b"")
    bf = len(f.content or b"")
    if bt == 0 or bb == 0:
        return None

    diff = abs(bt - bf) / max(bt, 1)
    base_diff = abs(bb - bt) / max(bb, 1)
    # Require the truthy/falsy delta to clear natural site noise by 3x; require
    # truthy to mirror baseline within the noise floor.
    required_signal = max(0.15, noise_floor * 3.0)
    if diff < required_signal or base_diff > max(0.10, noise_floor):
        return None

    url = client.url(f"/?{param}={baseline}")
    replay = build_replay_curl("GET", client.url("/"), params={param: baseline + QUOTE + TRUTHY})
    return Finding(
        severity="high",
        title=f"Possible boolean-based SQL injection in {desc}",
        evidence=(
            f"Differential lengths:\n"
            f"  baseline ?{param}={baseline}                          -> {bb} bytes\n"
            f"  truthy   ?{param}={baseline}{QUOTE}{TRUTHY}           -> {bt} bytes\n"
            f"  falsy    ?{param}={baseline}{QUOTE}{FALSY}            -> {bf} bytes\n"
            f"Truthy mirrors baseline (delta {base_diff:.0%}); falsy diverges by {diff:.0%}, "
            "suggesting the query is responding to attacker-controlled boolean logic."
        ),
        remediation=(
            "Verify manually with sqlmap or by reading the source. False positives are possible "
            "when sites randomize ad/widget content. If confirmed, locate the vulnerable code and "
            "switch to $wpdb->prepare()."
        ),
        url=url,
        extra={
            "provable": True,
            "prover": "sqli",
            "param": param,
            "vector": "boolean",
            "baseline_path": "/",
            "baseline_value": baseline,
            "replay": replay,
            "next_steps": [
                f'sqlmap -u "{url}" --batch --technique=B --risk=1 --level=2',
            ],
        },
    )


async def _probe_time(client: Client, param: str, baseline: str, desc: str) -> Finding | None:
    # Two warm-up requests to establish baseline
    t0 = time.perf_counter()
    await client.get("/", params={param: baseline})
    base_a = time.perf_counter() - t0
    t0 = time.perf_counter()
    await client.get("/", params={param: baseline})
    base_b = time.perf_counter() - t0
    base = max(base_a, base_b)

    payload = baseline + QUOTE + " AND (SELECT 1 FROM(SELECT(SLEEP(3)))a)-- -"
    t0 = time.perf_counter()
    r = await client.get("/", params={param: payload})
    delta = time.perf_counter() - t0
    if r is None:
        return None
    if delta - base >= 2.5:
        url = client.url(f"/?{param}={baseline}")
        replay = build_replay_curl("GET", client.url("/"), params={param: payload})
        return Finding(
            severity="critical",
            title=f"Time-based blind SQL injection in {desc}",
            evidence=(
                f"Baseline request: {base*1000:.0f} ms; SLEEP(3) payload: {delta*1000:.0f} ms.\n"
                f"  payload: ?{param}={payload}\n"
                "The 3-second delta strongly implies the database is executing attacker SQL."
            ),
            remediation=(
                "Treat this as a critical incident. Take the vulnerable plugin/theme offline immediately, "
                "review server access/error logs for prior exploitation, and rotate any credentials that "
                "may have been read via UNION/SELECT chains."
            ),
            url=url,
            extra={
                "provable": True,
                "prover": "sqli",
                "param": param,
                "vector": "time",
                "baseline_path": "/",
                "baseline_value": baseline,
                "replay": replay,
                "next_steps": [
                    f'sqlmap -u "{url}" --batch --technique=T --risk=2 --level=3',
                ],
            },
        )
    return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("calibrating natural response variance...")
    cal = await calibrate(client, "/", samples=3)
    noise = cal.max_delta_ratio
    if cal.is_unstable():
        findings.append(
            Finding(
                severity="info",
                title=f"Site response is unstable (variance {noise:.0%}) — boolean SQLi detection unreliable",
                evidence=(
                    f"3 identical GETs to / varied by {noise:.0%} in body size. "
                    "Dynamic ads/recommendations/A-B-tests typically cause this. "
                    "Boolean-based SQLi probes will be skipped to avoid false positives; "
                    "error- and time-based probes still run."
                ),
                remediation="No action needed — informational. If you want boolean detection here, scan a static page like /sample-page/ instead of /.",
                url=ctx["target"],
            )
        )

    for i, (param, baseline, desc) in enumerate(TARGETS):
        step(f"probing {desc} for error-based SQLi...")
        ef = await _probe_error(client, param, baseline, desc)
        if ef:
            findings.append(ef)
            continue
        if not cal.is_unstable():
            step(f"probing {desc} for boolean-based SQLi...")
            bf = await _probe_boolean(client, param, baseline, desc, noise)
            if bf:
                findings.append(bf)
                continue
        # Time-based is slow (each probe takes ~3s); only run on the first two endpoints.
        if i < 2:
            step(f"probing {desc} for time-based SQLi (this is slow)...")
            tf = await _probe_time(client, param, baseline, desc)
            if tf:
                findings.append(tf)

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No SQL injection indicators on tested parameters",
                evidence=(
                    f"Probed {len(TARGETS)} common WP parameters with error/boolean/time payloads. "
                    "WP core has long been hardened against these vectors; real-world WP SQLi usually "
                    "lives in plugins. This is reassuring but not exhaustive."
                ),
                remediation="No action needed for the tested endpoints. Keep all plugins updated and prefer plugins from reputable maintainers.",
                url=ctx["target"],
            )
        )
    return findings
