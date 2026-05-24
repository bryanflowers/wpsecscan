"""Round-59 #4-5 — Membership + LMS plugin audit.

#4 Membership: MemberPress, Paid Memberships Pro, Restrict Content Pro.
   Payment + access-control glue — historically the source of capability
   bypass and price-tampering CVEs.
#5 LMS: LearnDash, LifterLMS, TutorLMS, Sensei. Quiz-bypass, completion
   spoofing, certificate-IDOR are the big themes.

Each plugin's REST endpoints + protected-content paths are probed for
unauthenticated readability — the most common bug class.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


MEMBERSHIP = (
    ("MemberPress",          "/wp-content/plugins/memberpress/memberpress.php",
                             "/wp-json/mp/v1/members"),
    ("Paid Memberships Pro", "/wp-content/plugins/paid-memberships-pro/paid-memberships-pro.php",
                             "/wp-json/pmpro/v1/users"),
    ("Restrict Content Pro", "/wp-content/plugins/restrict-content-pro/restrict-content-pro.php",
                             "/wp-json/rcp/v1/members"),
)

LMS = (
    ("LearnDash",  "/wp-content/plugins/sfwd-lms/sfwd_lms.php",
                   "/wp-json/ldlms/v2/users"),
    ("LifterLMS",  "/wp-content/plugins/lifterlms/lifterlms.php",
                   "/wp-json/llms/v1/students"),
    ("TutorLMS",   "/wp-content/plugins/tutor/tutor.php",
                   "/wp-json/tutor/v1/courses"),
    ("Sensei LMS", "/wp-content/plugins/sensei-lms/sensei-lms.php",
                   "/wp-json/sensei/v1/courses"),
)
VERSION_RE = re.compile(r"Version:\s*([\d.]+)", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    def _full(p: str) -> str:
        return target + p

    for name, plugin_path, rest_path in MEMBERSHIP:
        step(f"membership probe {name}...")
        r = await client.get(plugin_path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = VERSION_RE.search(r.text)
        findings.append(Finding(
            severity="info",
            title=f"Membership plugin: {name} {m.group(1) if m else '?'} detected",
            evidence=f"{plugin_path} reachable.",
            remediation="Membership plugins gate paid content. Audit `permission_callback` on REST + AJAX.",
            url=_full(plugin_path),
        ))
        rr = await client.get(rest_path)
        if rr is not None and rr.status_code == 200 and rr.text:
            findings.append(Finding(
                severity="high",
                title=f"{name} REST endpoint readable unauthenticated",
                evidence=f"GET {rest_path} -> {rr.status_code} ({len(rr.text)} bytes).",
                remediation=f"Lock `{rest_path}` to authenticated callers via `permission_callback`. {name} ships defaults that are sometimes too permissive.",
                url=_full(rest_path),
            ))

    for name, plugin_path, rest_path in LMS:
        step(f"LMS probe {name}...")
        r = await client.get(plugin_path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = VERSION_RE.search(r.text)
        findings.append(Finding(
            severity="info",
            title=f"LMS plugin: {name} {m.group(1) if m else '?'} detected",
            evidence=f"{plugin_path} reachable.",
            remediation="LMS plugins commonly suffer quiz-bypass and certificate-IDOR. Audit nonce + per-user ownership checks.",
            url=_full(plugin_path),
        ))
        rr = await client.get(rest_path)
        if rr is not None and rr.status_code == 200 and rr.text:
            findings.append(Finding(
                severity="medium",
                title=f"{name} REST endpoint readable unauthenticated",
                evidence=f"GET {rest_path} -> {rr.status_code} ({len(rr.text)} bytes).",
                remediation=f"Add `permission_callback` requiring at least `read` capability on `{rest_path}`.",
                url=_full(rest_path),
            ))

    if not findings:
        return [Finding(severity="info", title="Membership/LMS audit — no plugins detected",
                        evidence="Probed 3 membership + 4 LMS plugins.",
                        remediation="No action.", url=target)]
    return findings
