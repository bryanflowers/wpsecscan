"""F16 (v2.8.1) — Next.js NEXT_PUBLIC_* env-var exposure probe.

Headless WP + Next.js sites bake `NEXT_PUBLIC_*` env vars into
the static chunks under `/_next/static/chunks/`. Developers often
accidentally label a private secret with the `NEXT_PUBLIC_` prefix,
which then ships to every client. We sniff a webpack chunk for
suspicious tokens.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_SECRET_PATTERNS = (
    (re.compile(r"NEXT_PUBLIC_[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD)"),
     "env var name labelled SECRET/KEY/TOKEN/PASSWORD but with NEXT_PUBLIC_ prefix"),
    (re.compile(r"NEXT_PUBLIC_[A-Z0-9_]*PRIVATE"),
     "NEXT_PUBLIC_*PRIVATE — contradiction by definition"),
    (re.compile(r"sk_live_[a-zA-Z0-9]{20,}"),
     "Stripe live secret key in client bundle"),
    (re.compile(r"sk-proj-[a-zA-Z0-9_-]{30,}"),
     "OpenAI project secret in client bundle"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F16: probing Next.js _next/static/chunks for env-var leaks")
    # Fetch the build-manifest to discover a chunk URL.
    bm = await client.get("/_next/static/buildManifest.js")
    if bm is None or bm.status_code != 200:
        return [Finding(severity="info",
                         title="F16: Next.js _next/ assets not detected",
                         evidence="No /_next/static/buildManifest.js — not a Next.js site.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    # Best-effort: grab any chunk path mentioned in the manifest.
    chunks = re.findall(r'"(static/chunks/[^"]+\.js)"', bm.text or "")[:3]
    findings: list[Finding] = []
    for chunk in chunks:
        r = await client.get("/_next/" + chunk)
        if r is None or r.status_code != 200:
            continue
        text = r.text or ""
        for pattern, label in _SECRET_PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(Finding(severity="high",
                                          title=f"F16: Next.js chunk leaks secret ({label})",
                                          evidence=f"/_next/{chunk}: matched {m.group(0)[:60]}",
                                          remediation=(
                                              "Rename the env var to remove the `NEXT_PUBLIC_` "
                                              "prefix so Next.js stops embedding it in the "
                                              "client bundle. Rotate the leaked secret IMMEDIATELY. "
                                              "Re-build and re-deploy."),
                                          url=ctx["target"]))
                break
    if not findings:
        findings.append(Finding(severity="info",
                                  title="F16: no obvious secret patterns in Next.js chunks",
                                  evidence=f"Inspected {len(chunks)} chunk(s).",
                                  remediation="No action needed.",
                                  url=ctx["target"]))
    return findings
