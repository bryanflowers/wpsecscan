"""Permissions-Policy header audit.

`Permissions-Policy` (formerly Feature-Policy) declares which powerful
browser APIs (camera, microphone, geolocation, payment, USB, etc.) are
allowed on the site. Most WordPress sites don't need any of them on by
default. Missing or over-permissive grants are an attack-surface item for
malicious advertising / supply-chain JS.

We also flag the absence of `interest-cohort=()` which is the documented
opt-out for Google's FLoC tracking (GDPR / ePrivacy signal).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


SENSITIVE_DIRECTIVES = (
    "camera", "microphone", "geolocation", "payment", "usb", "display-capture",
    "speaker-selection", "midi", "magnetometer", "accelerometer", "gyroscope",
    "fullscreen", "encrypted-media",
)


def _parse_policy(header_val: str) -> dict[str, str]:
    """Return {directive: allowlist-string} from a Permissions-Policy value."""
    out: dict[str, str] = {}
    if not header_val:
        return out
    for part in header_val.split(","):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            out[k.strip().lower()] = v.strip()
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("fetching homepage to read Permissions-Policy header...")
    r = await client.get("/")
    if r is None:
        return findings
    val = r.headers.get("Permissions-Policy") or r.headers.get("permissions-policy") or ""
    if not val:
        findings.append(Finding(
            severity="low",
            title="Permissions-Policy header missing",
            evidence="No Permissions-Policy header on /. Browsers will use defaults.",
            remediation=(
                "Add a deny-by-default header to disable powerful APIs you don't "
                "need. Example: `Permissions-Policy: camera=(), microphone=(), "
                "geolocation=(), payment=(), usb=(), interest-cohort=()` — the "
                "`interest-cohort=()` clause also opts the site out of Google FLoC."
            ),
            url=ctx["target"],
        ))
        return findings
    parsed = _parse_policy(val)

    # Detect dangerous `*` grants on sensitive directives
    over_permissive = []
    for d in SENSITIVE_DIRECTIVES:
        v = parsed.get(d, "")
        # `()` = empty allowlist (safe); `*` or `(*)` = any origin (dangerous);
        # `(self)` = same-origin only (typically fine).
        if v in ("*", "(*)"):
            over_permissive.append(d)
    if over_permissive:
        findings.append(Finding(
            severity="medium",
            title=f"Permissions-Policy grants `*` to {len(over_permissive)} sensitive directive(s)",
            evidence=f"Over-permissive directives: {', '.join(over_permissive)}\n"
                     f"Full header: {val[:300]}",
            remediation=(
                "Replace `*` with `()` (deny) or `(self)` (same-origin only) for "
                "directives the site doesn't use. Even if you embed a third party "
                "that needs camera/microphone, name them explicitly via "
                "`camera=(self \"https://meet.example.com\")` rather than `*`."
            ),
            url=ctx["target"],
        ))

    # Detect missing interest-cohort opt-out
    if "interest-cohort" not in parsed:
        findings.append(Finding(
            severity="low",
            title="Permissions-Policy is set but does not opt out of FLoC (`interest-cohort=()`)",
            evidence=f"Header present but missing the `interest-cohort` directive: {val[:200]}",
            remediation=(
                "Append `, interest-cohort=()` to opt this site out of Google "
                "FLoC/Topics behaviour-tracking. Has near-zero impact and is a "
                "GDPR/ePrivacy good-practice signal."
            ),
            url=ctx["target"],
        ))

    if not findings:
        findings.append(Finding(
            severity="info",
            title="Permissions-Policy header looks reasonable",
            evidence=f"Header: {val[:200]}",
            remediation="No action.",
            url=ctx["target"],
        ))
    return findings
