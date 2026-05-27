"""A25 (v2.6.0) — Search-result <mark>-highlight XSS probe.

Several search plugins (Relevanssi, SearchWP, plus core ?s= when a
theme wraps results in <mark>) wrap the user's search term in
`<mark>highlight</mark>` for visual emphasis. Many themes do this
without escaping the term first, producing reflected XSS via the `?s=`
query parameter.

Passive: probe `/?s=<svg/onload=alert(1)>` and check whether the
literal `<svg/onload` appears in the response body (unescaped).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PAYLOAD = "<svg/onload=wpsecscanXSSprobe>"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step(f"search XSS probe: /?s={_PAYLOAD}")
    r = await client.get("/", params={"s": _PAYLOAD})
    if r is None or not r.text:
        return findings

    body = r.text
    if _PAYLOAD in body or "wpsecscanXSSprobe" in body and "<svg" in body:
        findings.append(Finding(
            severity="high",
            title="Reflected XSS via search-result highlight (?s=)",
            evidence=(
                f"GET /?s={_PAYLOAD} → HTTP {r.status_code}\n"
                f"Response body contains the unescaped payload at: "
                f"{body.find(_PAYLOAD)}\n"
                "Excerpt around the reflection:\n  "
                + body[max(0, body.find(_PAYLOAD) - 80):body.find(_PAYLOAD) + 200].replace("\n", " ")
            ),
            remediation=(
                "1. Open the theme's search.php (or the active search plugin's\n"
                "   highlight template) and pass the search term through\n"
                "   esc_html() before injecting into <mark>.\n"
                "2. For Relevanssi specifically, set relevanssi_highlight_no_tags\n"
                "   to true OR update to >= 4.22.\n"
                "3. Until fixed, add a WAF rule blocking <svg / <iframe /\n"
                "   <script substrings in ?s= query params."
            ),
            url=client.url(f"/?s={_PAYLOAD}"),
            extra={"category": "reflected-xss"},
        ))
    return findings
