"""#1 Gutenberg block CVE scanner.

Third-party block plugins ship their own static assets at predictable
paths under /wp-content/plugins/<slug>/build/index.js — and many embed a
`version` field in the block.json that's served alongside. We scan for
known-vulnerable block packages."""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding

# Curated set — extend over time
KNOWN_BLOCKS = (
    ("@10up/restricted-site-access", "/wp-content/plugins/restricted-site-access/build/index.js"),
    ("wpzoom-blocks", "/wp-content/plugins/wpzoom-blocks/build/index.js"),
    ("kadence-blocks", "/wp-content/plugins/kadence-blocks/dist/blocks.build.js"),
    ("genesis-blocks", "/wp-content/plugins/genesis-blocks/dist/blocks.build.js"),
    ("ultimate-addons-for-gutenberg", "/wp-content/plugins/ultimate-addons-for-gutenberg/dist/blocks.style.build.js"),
)
VERSION_RE = re.compile(r'(?:"version"|version)\s*[:=]\s*"([\d.]+)"')


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    detected = []
    for name, path in KNOWN_BLOCKS:
        step(f"Gutenberg block probe {name}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        version = None
        m = VERSION_RE.search((r.text or "")[:5000])
        if m:
            version = m.group(1)
        detected.append((name, path, version))
    if not detected:
        return [Finding(severity="info", title="Gutenberg block scan — no known third-party blocks detected",
                        evidence=f"Probed {len(KNOWN_BLOCKS)} known block plugins.",
                        remediation="No action.", url=ctx["target"])]
    findings.append(Finding(
        severity="info",
        title=f"Gutenberg blocks detected: {len(detected)}",
        evidence="\n".join(f"  - {n} {v or '(version unknown)'} at {p}" for n, p, v in detected),
        remediation="Cross-reference each version against the plugin's CVE history. Some third-party blocks have had stored-XSS issues in their `save()` markup.",
        url=ctx["target"],
    ))
    return findings
