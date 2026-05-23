"""H10 Header smuggling via case sensitivity / duplication.

HTTP says header names are case-insensitive. In practice, some proxies fold
duplicates by joining values, others by picking the first, others by picking
the last. A request like:

    Content-Length: 11
    content-length: 4
    Body: x=1&y=22

results in front-end / back-end disagreeing on where the request ends, which
is the desync precondition.

We send a few crafted requests with case-variant or duplicate headers and
watch for asymmetric behaviour (status code or body length differs from the
baseline). This is much narrower than the full smuggling_probe check — it
only catches the case-normalisation class of disagreement.

Aggressive only — sending non-conformant headers may trip WAF rules.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


PROBES = (
    # (label, headers dict)
    ("Content-Length case duplicate",
     {"Content-Length": "0", "content-length": "0"}),
    ("Transfer-Encoding case-variant",
     {"Transfer-Encoding": "chunked", "transfer-encoding": "chunked"}),
    ("X-Forwarded-For + X-Forwarded-FOR (case-variant)",
     {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-FOR": "8.8.8.8"}),
    ("Host case-variant",
     {"hOsT": "example.com"}),
    ("Content-Type duplicated",
     {"Content-Type": "application/json", "content-type": "text/plain"}),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(Finding(
            severity="info",
            title="Header smuggling case-sensitivity probe skipped (passive mode)",
            evidence="Pass --aggressive to enable.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    step("baselining / for header-case comparison...")
    baseline = await client.get("/")
    if baseline is None:
        findings.append(Finding(
            severity="info",
            title="Header smuggling probe — baseline / unreachable",
            evidence="Couldn't fetch / to baseline.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    base_status = baseline.status_code
    base_len = len(baseline.content or b"")

    deltas: list[tuple[str, int, int]] = []
    for label, hdrs in PROBES:
        step(f"probing {label}...")
        r = await client.get("/", headers=hdrs)
        if r is None:
            continue
        delta = abs(len(r.content or b"") - base_len)
        if r.status_code != base_status or delta > 800:
            deltas.append((label, r.status_code, delta))

    if deltas:
        findings.append(Finding(
            severity="medium",
            title=f"Header case-sensitivity differential — {len(deltas)} variant(s) changed response",
            evidence="\n".join(
                f"  - {l}: status={s}, body delta {d} bytes vs baseline (HTTP {base_status}, {base_len}B)"
                for l, s, d in deltas
            ) + (
                "\n\nWhen a proxy and the backend disagree about how to handle duplicate or case-variant "
                "headers, that disagreement IS the request-smuggling precondition. Worth pairing with "
                "the smuggling_probe check for active CL.TE/TE.CL confirmation."
            ),
            remediation=(
                "Use a normalising proxy (nginx, HAProxy, Envoy) that rejects duplicate critical headers "
                "(Content-Length, Transfer-Encoding) outright with 400 Bad Request. nginx does this by "
                "default; if you're terminating TLS in app code, you've likely got a custom parser worth "
                "auditing."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="Header case-sensitivity probe — no differential observed",
            evidence=f"Probed {len(PROBES)} header variants; none caused a meaningful response change.",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
