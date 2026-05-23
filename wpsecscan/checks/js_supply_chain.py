"""JS + CSS supply-chain inventory.

Inventories every external host serving JS and stylesheets to your pages,
and flags unpinned references (no SRI hash). Both `<script src>` and
`<link rel=stylesheet>` are an SRI risk — a CDN compromise can poison your
JS via either vector.

Risky hosts (raw GitHub, unfamiliar CDNs) get higher severity than well-known
ones (jsdelivr, unpkg with SRI).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

SCRIPT_TAG_RE = re.compile(
    r"<script\b[^>]*\bsrc=['\"]([^'\"]+\.js)[^'\"]*['\"][^>]*>",
    re.IGNORECASE,
)
# CSS: <link rel="stylesheet" href="...">  (rel/href order may vary)
LINK_TAG_RE = re.compile(
    r"""<link\b[^>]*?\brel\s*=\s*['"]\s*stylesheet\s*['"][^>]*?\bhref\s*=\s*['"]([^'"]+)['"][^>]*>"""
    r"""|<link\b[^>]*?\bhref\s*=\s*['"]([^'"]+)['"][^>]*?\brel\s*=\s*['"]\s*stylesheet\s*['"][^>]*>""",
    re.IGNORECASE,
)
INTEGRITY_RE = re.compile(r"\bintegrity=['\"](sha\d+-[A-Za-z0-9+/=]+)['\"]", re.IGNORECASE)

# Heuristic "well-known" CDN hosts. SRI is recommended for any of them.
KNOWN_CDNS = ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "code.jquery.com",
              "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com", "ajax.googleapis.com",
              "cdn.cloudflare.com")
# Hosts that are essentially "execute someone else's repo as your site code"
HIGH_RISK_HOSTS = ("raw.githubusercontent.com", "gist.githubusercontent.com",
                   "rawgit.com", "gitcdn.link", "cdn.rawgit.com")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    own_host = urlparse(ctx["target"]).hostname or ""

    # (host, count, has_sri_anywhere)
    inventory: dict[str, dict] = {}

    def _record(src: str, tag_text: str, asset_kind: str) -> None:
        """Record one external asset reference into the inventory."""
        if src.startswith("//"):
            src = "https:" + src
        if src.startswith(("http://", "https://")):
            host = urlparse(src).hostname or ""
        else:
            return  # relative — same origin, skip
        if not host or host == own_host or host.endswith("." + own_host):
            return
        has_sri = bool(INTEGRITY_RE.search(tag_text))
        entry = inventory.setdefault(host, {"count": 0, "sri_count": 0, "samples": [], "kinds": set()})
        entry["count"] += 1
        if has_sri:
            entry["sri_count"] += 1
        if len(entry["samples"]) < 3:
            entry["samples"].append(f"[{asset_kind}] {src[:115]}")
        entry["kinds"].add(asset_kind)

    for path in ("/", "/wp-login.php", "/?p=1", "/sample-page/"):
        step(f"scanning {path} for external JS + CSS hosts...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        body = r.text
        for m in SCRIPT_TAG_RE.finditer(body):
            _record(m.group(1), m.group(0), "JS")
        # A8: cover CSS the same way — a poisoned stylesheet can execute JS via
        # `expression()` (IE legacy), via `behavior:url(...)`, via `@import` to
        # an attacker URL, or simply by carrying tracking pixels / web fonts.
        for m in LINK_TAG_RE.finditer(body):
            src = m.group(1) or m.group(2)
            if src:
                _record(src, m.group(0), "CSS")

    if not inventory:
        findings.append(
            Finding(
                severity="info",
                title="No external JS / CSS hosts loaded",
                evidence="All <script src> and <link rel=stylesheet> references resolve to the same origin.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # Summary finding
    lines = []
    for host, info in sorted(inventory.items(), key=lambda kv: -kv[1]["count"]):
        sri = "SRI" if info["sri_count"] == info["count"] else f"{info['sri_count']}/{info['count']} SRI"
        kinds = "+".join(sorted(info["kinds"]))
        lines.append(f"  - {host:42}  refs={info['count']:>3}  [{sri}]  ({kinds})")
    findings.append(
        Finding(
            severity="info",
            title=f"External JS+CSS hosts inventory: {len(inventory)} unique host(s)",
            evidence="\n".join(lines),
            remediation="No action needed for the inventory itself — see follow-up findings for risky entries.",
            url=ctx["target"],
        )
    )

    # Risky entries
    for host, info in inventory.items():
        if host in HIGH_RISK_HOSTS:
            findings.append(
                Finding(
                    severity="high",
                    title=f"JS loaded from high-risk host: {host}",
                    evidence=(
                        f"{info['count']} <script src=> reference(s) to {host}\n"
                        f"Samples:\n  " + "\n  ".join(info["samples"]) + "\n\n"
                        f"{host} serves raw repository content — any commit by the repo owner replaces your "
                        "production JS instantly. There's no review gate."
                    ),
                    remediation=(
                        "Replace with a versioned-and-pinned CDN (jsdelivr.net, unpkg.com) using an integrity hash. "
                        "Or self-host the script after pinning to a specific commit hash."
                    ),
                    url=ctx["target"],
                )
            )
            continue
        if info["sri_count"] < info["count"]:
            unpinned = info["count"] - info["sri_count"]
            kinds = "+".join(sorted(info["kinds"]))
            sev = "medium" if host in KNOWN_CDNS else "high"
            findings.append(
                Finding(
                    severity=sev,
                    title=f"{unpinned} {kinds} reference(s) to {host} without SRI hash",
                    evidence=(
                        f"{host}: {unpinned}/{info['count']} references have no `integrity=` attribute.\n"
                        f"Asset kinds present: {kinds}\n"
                        f"Samples:\n  " + "\n  ".join(info["samples"]) + "\n\n"
                        "Without SRI, the CDN can serve any modified content (compromised, swapped, replaced). "
                        "This applies to BOTH <script src> and <link rel=stylesheet> — a poisoned stylesheet "
                        "can execute behavior:url(), serve tracking pixels, or use @import to fetch attacker JS."
                    ),
                    remediation=(
                        "Add Subresource Integrity hashes to every external asset:\n"
                        "  <script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>\n"
                        "  <link rel=\"stylesheet\" href=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\">\n"
                        "Generate hashes via https://www.srihash.org"
                    ),
                    url=ctx["target"],
                )
            )

    return findings
