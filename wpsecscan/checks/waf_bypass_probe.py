"""WAF bypass / passthrough probe.

After the `waf` check has detected a WAF, this probes whether it actually
FILTERS or just fingerprints. We send a benign-looking but WAF-trigger string
in a query parameter and compare the response against a control.

If the WAF blocks: status 403/406/501 or response body wildly different.
If the WAF passes the trigger through: same response shape as control → flag.

Aggressive-only (sends a `<script>` token).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

TRIGGER_PAYLOADS = (
    ("/?wpsec_test=<script>alert(1)</script>", "XSS reflected probe"),
    ("/?wpsec_test=' OR 1=1--", "SQLi UNION boilerplate"),
    ("/?wpsec_test=../../../etc/passwd", "path-traversal"),
    ("/?wpsec_test=javascript:alert(1)", "javascript scheme"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="WAF bypass probe skipped (requires --aggressive)",
                evidence="This check sends known-evil-looking query strings to test if your WAF filters them.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    waf_list = ctx.get("shared", {}).get("waf") or []
    if not waf_list:
        findings.append(
            Finding(
                severity="info",
                title="WAF bypass probe skipped — no WAF detected",
                evidence="The `waf` check didn't fingerprint a WAF; nothing to test bypass against.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Control
    step("baselining control response on /...")
    ctrl = await client.get("/", params={"wpsec_test": "harmless-string"})
    if ctrl is None:
        findings.append(
            Finding(
                severity="info",
                title="WAF bypass probe — control request failed",
                evidence="Couldn't establish a control response; aborting.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings
    ctrl_len = len((ctrl.text or ""))
    ctrl_code = ctrl.status_code

    passes: list[tuple[str, str, int, int]] = []  # (path, label, code, len)
    blocked: list[tuple[str, str, int]] = []     # (path, label, code)
    for path, label in TRIGGER_PAYLOADS:
        step(f"probing WAF with {label}...")
        r = await client.get(path)
        if r is None:
            continue
        body_len = len(r.text or "")
        # Strong block signal: 403 / 406 / 419 / 501 / 999
        if r.status_code in (403, 406, 419, 501, 999):
            blocked.append((path, label, r.status_code))
            continue
        # Same response shape as control → WAF didn't block
        if r.status_code == ctrl_code and abs(body_len - ctrl_len) < max(200, ctrl_len * 0.10):
            passes.append((path, label, r.status_code, body_len))

    if blocked and not passes:
        findings.append(
            Finding(
                severity="info",
                title=f"WAF ({', '.join(waf_list)}) blocks all {len(blocked)} bypass probes",
                evidence="Blocked: " + ", ".join(f"{lbl} ({code})" for _p, lbl, code in blocked),
                remediation="No action — WAF is filtering as expected.",
                url=ctx["target"],
            )
        )
        return findings

    if passes:
        findings.append(
            Finding(
                severity="medium",
                title=f"WAF ({', '.join(waf_list)}) passes {len(passes)} bypass payload(s) through",
                evidence=(
                    "Payloads that the WAF allowed (same response shape as control):\n"
                    + "\n".join(f"  • {lbl}  →  HTTP {code}  ({bl} bytes)" for _p, lbl, code, bl in passes)
                    + "\n\nThis doesn't mean the underlying app is vulnerable — just that the WAF "
                      "isn't filtering these payload classes. The aggressive `sqli` / `xss_reflected` "
                      "checks will exercise the actual app."
                ),
                remediation=(
                    "Verify the WAF ruleset has OWASP CRS Core (or the equivalent on your CDN) enabled. "
                    "Cloudflare: 'Managed Rules' under Security; AWS WAF: managed rule group "
                    "`AWSManagedRulesCommonRuleSet`; Wordfence (host-side): turn on extended "
                    "protection mode."
                ),
                url=ctx["target"],
            )
        )
    return findings
