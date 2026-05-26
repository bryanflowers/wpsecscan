"""REST API response-size DoS amplification probe.

WordPress's REST API supports `?_fields=*` which expands every field on
every returned resource. On plugin-heavy sites (especially WooCommerce)
this can produce uncompressed responses of several MB from a single
request — a cheap amplification vector for bandwidth-bill DoS.

Passive measurement: one GET with `Accept-Encoding: identity` (no gzip)
to /wp-json/?_fields=* and check the response size against a 500 KB
threshold.
"""
from __future__ import annotations
from ..http import Client
from ..models import Finding

_THRESHOLD_BYTES = 500 * 1024  # 500 KB


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("measuring uncompressed /wp-json/?_fields=* response size...")
    r = await client.get("/wp-json/?_fields=*", headers={"Accept-Encoding": "identity"})
    if r is None or r.status_code != 200:
        return findings
    size = len(r.content or b"")
    if size < _THRESHOLD_BYTES:
        findings.append(Finding(
            severity="info",
            title=f"REST root with _fields=* is {size/1024:.0f} KB (within threshold)",
            evidence=f"GET /wp-json/?_fields=* → {size} bytes (uncompressed).",
            remediation="No action.",
            url=client.url("/wp-json/?_fields=*"),
        ))
        return findings
    findings.append(Finding(
        severity="medium",
        title=f"REST root with _fields=* is {size/1024:.0f} KB — DoS amplification vector",
        evidence=(
            f"GET /wp-json/?_fields=* (no compression) → {size:,} bytes.\n"
            "An attacker who can make repeated requests against this URL can "
            "saturate bandwidth quickly: one short request → hundreds of KB out, "
            "amplification ratio in the hundreds-to-thousands range. CDNs often "
            "don't cache `?_fields=*` (different query strings → different keys)."
        ),
        remediation=(
            "Rate-limit /wp-json/ at the WAF or reverse proxy. Cloudflare: add a "
            "rule limiting /wp-json/* to ~5 req/sec per IP. Nginx: `limit_req "
            "zone=rest burst=10` on `location /wp-json/`. Also consider rejecting "
            "_fields=* explicitly via a filter: it's an admin convenience, not a "
            "public-API contract."
        ),
        url=client.url("/wp-json/?_fields=*"),
        extra={"response_bytes": size},
    ))
    return findings
