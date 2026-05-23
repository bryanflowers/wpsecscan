"""WooCommerce-specific audit.

WooCommerce sites are the highest-value WP targets — PII + payment data.
Probes:
  - /wp-json/wc/v3/ namespace reachability (information disclosure)
  - /wp-json/wc/v3/orders, /customers, /products with OPTIONS to see which
    methods are exposed unauthenticated
  - ?wc-api=<endpoint> remnants (legacy v1 API; should be disabled)
  - Common WC plugin paths that often leak (Subscriptions, Bookings, etc.)
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

WC_REST_NAMESPACES = (
    "/wp-json/wc/v3/products",
    "/wp-json/wc/v3/customers",
    "/wp-json/wc/v3/orders",
    "/wp-json/wc/v3/system_status",
    "/wp-json/wc/v3/data",
    "/wp-json/wc-store/v1/products",  # WC Blocks store API
    "/wp-json/wc-analytics/products",
)

WC_LEGACY_API = (
    "?wc-api=wc_gateway_paypal",
    "?wc-api=wc_gateway_stripe",
    "?wc-api=woocommerce_paypal_ipn",
)

WC_PLUGIN_PATHS = (
    "/wp-content/plugins/woocommerce/readme.txt",
    "/wp-content/plugins/woocommerce-subscriptions/readme.txt",
    "/wp-content/plugins/woocommerce-bookings/readme.txt",
    "/wp-content/plugins/woocommerce-memberships/readme.txt",
    "/wp-content/plugins/woocommerce-payments/readme.txt",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Detect WooCommerce via the / page or /wp-json/wc/v3/
    step("detecting WooCommerce...")
    r = await client.get("/wp-json/wc/v3/")
    is_woo = False
    if r is not None and r.status_code in (200, 401, 403) and ("wc/v3" in (r.text or "") or "woocommerce" in (r.text or "").lower()):
        is_woo = True
    if not is_woo:
        r2 = await client.get("/")
        if r2 is not None and "woocommerce" in (r2.text or "").lower():
            is_woo = True

    if not is_woo:
        findings.append(
            Finding(
                severity="info",
                title="WooCommerce not detected — WC-specific audit skipped",
                evidence="Neither /wp-json/wc/v3/ nor the homepage indicated WooCommerce is installed.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    # Probe REST namespaces — flag any returning 200 without auth
    leaked_ns: list[tuple[str, int, int]] = []
    for path in WC_REST_NAMESPACES:
        step(f"probing WC REST {path}...")
        r = await client.get(path)
        if r is None:
            continue
        # 200 with a JSON body of actual records is the leak
        if r.status_code == 200 and r.content and len(r.content) > 50:
            try:
                import json as _j
                data = _j.loads(r.text)
                count = len(data) if isinstance(data, list) else 1
            except (ValueError, TypeError):
                count = 1
            leaked_ns.append((path, r.status_code, count))

    # Probe OPTIONS to see which write methods are advertised on each namespace
    write_methods: list[tuple[str, str]] = []
    for path in WC_REST_NAMESPACES:
        r = await client.request("OPTIONS", path)
        if r is None or r.status_code not in (200, 204):
            continue
        allow = (r.headers.get("allow", "") or r.headers.get("Allow", ""))
        writes = [m.strip() for m in allow.split(",") if m.strip() in ("POST", "PUT", "PATCH", "DELETE")]
        if writes:
            write_methods.append((path, ", ".join(writes)))

    # Probe legacy wc-api endpoints
    legacy_hits: list[str] = []
    for q in WC_LEGACY_API:
        r = await client.get("/" + q.lstrip("?"))
        if r is None:
            continue
        if r.status_code == 200:
            legacy_hits.append(q)

    # Plugin presence
    plugins_present: list[str] = []
    for p in WC_PLUGIN_PATHS:
        r = await client.get(p)
        if r is not None and r.status_code == 200:
            plugins_present.append(p)

    # Build findings
    if leaked_ns:
        for path, code, count in leaked_ns:
            sev = "critical" if any(k in path for k in ("orders", "customers")) else "high"
            findings.append(
                Finding(
                    severity=sev,
                    title=f"WC REST namespace {path} leaks data unauthenticated (HTTP {code}, ~{count} records)",
                    evidence=(
                        f"GET {path} returned {code} with content. The WooCommerce REST API should "
                        "require authentication for orders/customers/system_status. Unauthenticated "
                        "reads expose PII + business intel."
                    ),
                    remediation=(
                        "Confirm 'REST API' under WooCommerce → Settings → Advanced has 'Permission' "
                        "set; if so, the leak is a plugin overriding the auth check. Audit any plugin "
                        "that calls `register_rest_route` against the `wc/v3` namespace. Or add at the "
                        "edge: Nginx `location ~ ^/wp-json/wc { allow <office-ip>; deny all; }`."
                    ),
                    url=client.url(path),
                )
            )

    if write_methods:
        for path, methods in write_methods:
            sev = "high" if "DELETE" in methods or "PUT" in methods else "medium"
            findings.append(
                Finding(
                    severity=sev,
                    title=f"WC REST {path} advertises write methods: {methods}",
                    evidence=(
                        f"OPTIONS {path} -> Allow: {methods}. OPTIONS reflects every registered method "
                        "even if auth is enforced — verify each method actually rejects anonymous writes."
                    ),
                    remediation=(
                        "Test the actual write: `curl -X POST {path} -d 'test=1'`. If 401/403, you're OK. "
                        "If 200/201, you have unauth writes."
                    ),
                    url=client.url(path),
                )
            )

    if legacy_hits:
        findings.append(
            Finding(
                severity="medium",
                title=f"WooCommerce legacy ?wc-api= endpoints still reachable ({len(legacy_hits)})",
                evidence=f"Reachable: {', '.join(legacy_hits)}",
                remediation=(
                    "The legacy wc-api was deprecated in WC 3.0; modern installs should use /wp-json/wc/v3/. "
                    "Disable via plugin or in functions.php: `remove_action('parse_request', 'wc_api_handler');`"
                ),
                url=ctx["target"],
            )
        )

    if plugins_present:
        findings.append(
            Finding(
                severity="info",
                title=f"WooCommerce ecosystem plugins detected ({len(plugins_present)})",
                evidence="Found: " + ", ".join(plugins_present),
                remediation=(
                    "Cross-reference each plugin's version with the Wordfence CVE database "
                    "(run `wpsecscan --update-db` for fresh data). WC Subscriptions and WC Payments "
                    "have had multiple unauth-vulns in 2024."
                ),
                url=ctx["target"],
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="WooCommerce detected — no obvious REST or legacy-API leaks",
                evidence="REST namespaces require auth, no legacy wc-api endpoints reachable.",
                remediation="No action.",
                url=ctx["target"],
            )
        )

    return findings
