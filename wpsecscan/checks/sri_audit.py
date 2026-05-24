"""Round-62 #B24 — Subresource Integrity (SRI) audit.

For every <script src> and <link rel="stylesheet" href> from a different
origin, check whether `integrity=` is set. Missing SRI on a CDN resource
means an attacker controlling the CDN (or successful BGP hijack / cache
poisoning) can swap the code for arbitrary JS/CSS.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


SCRIPT_TAG_RE = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
LINK_STYLE_RE = re.compile(r"<link\b([^>]*\brel\s*=\s*[\"\']?stylesheet[\"\']?[^>]*)>", re.IGNORECASE)
SRC_ATTR_RE = re.compile(r"\bsrc\s*=\s*[\"\']([^\"\']+)[\"\']", re.IGNORECASE)
HREF_ATTR_RE = re.compile(r"\bhref\s*=\s*[\"\']([^\"\']+)[\"\']", re.IGNORECASE)
INTEGRITY_RE = re.compile(r"\bintegrity\s*=\s*[\"\']?(sha(?:256|384|512)-[A-Za-z0-9+/=]+)[\"\']?", re.IGNORECASE)
CROSSORIGIN_RE = re.compile(r"\bcrossorigin\s*=", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")
    target_host = urlparse(target).hostname or ""

    step("SRI audit: fetching home...")
    r = await client.get("/")
    if r is None or not r.text:
        return [Finding(severity="info", title="SRI audit — no home page",
                        evidence="", remediation="No action.", url=target)]
    body = r.text[:300_000]

    missing_sri: list[str] = []
    weak_hash: list[str] = []
    missing_crossorigin: list[str] = []

    def _process(tag_attr: str, src_re: re.Pattern, kind: str) -> None:
        src_m = src_re.search(tag_attr)
        if not src_m:
            return
        src = src_m.group(1)
        if not src.startswith(("http://", "https://")):
            return  # relative URL — same-origin, SRI not required
        src_host = urlparse(src).hostname or ""
        if not src_host or src_host == target_host or src_host.endswith("." + target_host):
            return  # same-origin
        integrity_m = INTEGRITY_RE.search(tag_attr)
        if not integrity_m:
            missing_sri.append(f"{kind}: {src[:120]}")
            return
        # SRI present — confirm strong hash + crossorigin attr
        algo = integrity_m.group(1).split("-", 1)[0].lower()
        if algo == "sha256":
            weak_hash.append(f"{kind}: {src[:120]}  ({algo})")
        if not CROSSORIGIN_RE.search(tag_attr):
            missing_crossorigin.append(f"{kind}: {src[:120]}")

    for m in SCRIPT_TAG_RE.finditer(body):
        _process(m.group(1), SRC_ATTR_RE, "script")
    for m in LINK_STYLE_RE.finditer(body):
        _process(m.group(1), HREF_ATTR_RE, "link[stylesheet]")

    if missing_sri:
        findings.append(Finding(
            severity="medium",
            title=f"SRI missing on {len(missing_sri)} cross-origin resource(s)",
            evidence="\n".join(f"  - {l}" for l in missing_sri[:15]),
            remediation=("Add `integrity=\"sha384-...\"` + `crossorigin=\"anonymous\"` to every "
                          "cross-origin <script> / <link rel=stylesheet>. Generate with "
                          "`curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A`"),
            url=target,
        ))
    if weak_hash:
        findings.append(Finding(
            severity="low",
            title=f"SRI present but using sha256 ({len(weak_hash)} resource(s))",
            evidence="\n".join(f"  - {l}" for l in weak_hash[:10]),
            remediation="Upgrade to sha384 — recommended baseline for SRI (sha256 still acceptable but defence-in-depth).",
            url=target,
        ))
    if missing_crossorigin:
        findings.append(Finding(
            severity="low",
            title=f"SRI present without `crossorigin` attr on {len(missing_crossorigin)} resource(s)",
            evidence="\n".join(f"  - {l}" for l in missing_crossorigin[:10]),
            remediation="Add `crossorigin=\"anonymous\"` — without it, the SRI check may silently fail on cross-origin resources.",
            url=target,
        ))

    if not findings:
        return [Finding(severity="info", title="SRI audit — all cross-origin resources are integrity-protected",
                        evidence=f"Checked {len(SCRIPT_TAG_RE.findall(body))} <script> + {len(LINK_STYLE_RE.findall(body))} <link stylesheet>.",
                        remediation="No action.", url=target)]
    return findings
