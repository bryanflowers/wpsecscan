"""F1 (v2.8.0) — WooCommerce coupon-code enumeration probe.

Brute-force coupon discovery is a documented WC fraud pattern (Wordfence
2024 + 2025 incident write-ups). Attackers probe the WC Store API
(`/wp-json/wc/store/v1/cart/apply-coupon`) or the legacy AJAX endpoint
(`?wc-ajax=apply_coupon`) with dictionary codes; valid codes are
revealed by the response shape ("Coupon applied" vs "Coupon does not
exist"), and the operator's discount structure leaks.

This check is DEFENSIVE: we probe with 5 obviously-fake codes and
detect whether the endpoint responds in a way that distinguishes
valid-from-invalid codes (which would enable a brute-force attack).
We do NOT actually try a real dictionary — that would be offensive
and would also trigger WAF blocks.

Output: a single finding if the endpoint distinguishes outcomes, OR
an info finding noting WC was not detected on the target.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PROBE_CODES = (
    "wpsecscan-probe-aaaa-0001",
    "wpsecscan-probe-aaaa-0002",
    "ZZZZZZZZ-NEVER-EXISTS",
    "save-50-percent-now",     # plausible-looking but vanishingly unlikely
    "test123",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # First confirm WC is on the target via the Store API root.
    step("F1: probing /wp-json/wc/store/v1/ to confirm WooCommerce...")
    root = await client.get("/wp-json/wc/store/v1/")
    has_wc = root is not None and root.status_code in (200, 401, 403)
    if not has_wc:
        findings.append(Finding(
            severity="info",
            title="F1: WooCommerce Store API not detected — coupon-enum probe skipped",
            evidence="GET /wp-json/wc/store/v1/ did not respond with a WC marker.",
            remediation="No action needed; this check only applies to WooCommerce sites.",
            url=ctx["target"],
        ))
        return findings

    # Apply 5 fake codes and collect the response shapes.
    step("F1: applying 5 fake coupon codes to detect enumeration oracle...")
    response_shapes: list[tuple[int, int]] = []  # (status, body_len)
    for code in _PROBE_CODES:
        try:
            r = await client.post(
                "/wp-json/wc/store/v1/cart/apply-coupon",
                json={"code": code},
            )
        except Exception:  # noqa: BLE001
            continue
        if r is None:
            continue
        body_len = len(r.text or "")
        response_shapes.append((r.status_code, body_len))

    if len(response_shapes) < 3:
        findings.append(Finding(
            severity="info",
            title="F1: coupon-apply endpoint unreachable — couldn't profile enumeration risk",
            evidence=f"Only {len(response_shapes)} of 5 probes returned a response.",
            remediation=(
                "Either WC is misconfigured, or the apply-coupon endpoint is rate-"
                "limited/blocked — both of which incidentally mitigate coupon "
                "enumeration. Verify the endpoint behaves as expected for real "
                "customers."
            ),
            url=ctx["target"],
        ))
        return findings

    # All 5 fake codes should produce the SAME response (all invalid →
    # all identical). If the responses vary materially, the endpoint
    # leaks an oracle that distinguishes valid from invalid codes —
    # which is exactly what a brute-force attacker exploits.
    unique_shapes = set(response_shapes)
    if len(unique_shapes) > 1:
        findings.append(Finding(
            severity="medium",
            title="F1: WC coupon-apply endpoint leaks an enumeration oracle",
            evidence=(
                f"5 distinct fake codes produced {len(unique_shapes)} different "
                f"response shapes (status, body-len): {sorted(unique_shapes)}. "
                "A brute-force attacker dictionary-attacking your coupon space "
                "can detect valid codes by the response shape divergence."
            ),
            remediation=(
                "Add rate-limiting to /wp-json/wc/store/v1/cart/apply-coupon "
                "(Wordfence / WP Cerber / Cloudflare rate-rules all work). "
                "Consider returning a uniform response for all unknown codes "
                "(generic 'invalid' message + identical status). For high-"
                "value coupons, gate via a one-time link / authenticated "
                "session rather than a public code."
            ),
            url=ctx["target"],
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="F1: WC coupon-apply endpoint returns uniform response for unknown codes",
            evidence=f"All 5 fake probes produced the same response shape: {next(iter(unique_shapes))}.",
            remediation="No action needed; coupon-enumeration oracle is not exposed.",
            url=ctx["target"],
        ))
    return findings
