"""WordPress REST API surface audit.

Probes /wp-json/ and common REST endpoints beyond /users (which the existing
users check covers). Flags exposed data the site owner may not realize is
publicly readable.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (endpoint, what-it-leaks, severity-if-200)
# Each tuple: path, description, severity_if_200, expected-not-empty-marker
REST_ENDPOINTS: tuple[tuple[str, str, str, str], ...] = (
    ("/wp-json/",                           "REST root index — lists every plugin and route", "info",   "namespaces"),
    ("/wp-json/wp/v2/posts",                "All public + private metadata for posts",         "info",   '"id"'),
    ("/wp-json/wp/v2/pages",                "All published pages",                              "info",   '"id"'),
    ("/wp-json/wp/v2/comments",             "Comment list including author emails on some confs", "low", '"author"'),
    ("/wp-json/wp/v2/categories",           "Category tree",                                    "info",   '"id"'),
    ("/wp-json/wp/v2/tags",                 "Tag list",                                         "info",   '"id"'),
    ("/wp-json/wp/v2/media",                "Uploaded media files (including unpublished)",    "low",    '"id"'),
    ("/wp-json/wp/v2/settings",             "WP options/settings — should NEVER be public",     "high",   '"title"'),
    ("/wp-json/wp/v2/themes",               "Installed themes list",                            "low",    '"stylesheet"'),
    ("/wp-json/wp/v2/plugins",              "Installed plugins list",                           "medium", '"plugin"'),
    ("/wp-json/wp/v2/blocks",               "Reusable blocks (may leak draft content)",         "low",    '"slug"'),
    ("/wp-json/wp/v2/types",                "Custom post type definitions",                     "info",   '"slug"'),
    ("/wp-json/wp/v2/statuses",             "Post status definitions",                          "info",   '"slug"'),
    # Plugin-specific endpoints that commonly leak data
    ("/wp-json/contact-form-7/v1/contact-forms", "Contact Form 7 form list",                    "low",    '"id"'),
    ("/wp-json/wc/v3/products",             "WooCommerce product list (rarely should be open)", "low",    '"id"'),
    ("/wp-json/wc-admin/options",           "WooCommerce admin options",                        "medium", '"option"'),
    ("/wp-json/jetpack/v4/connection",      "Jetpack connection metadata",                      "low",    '"connectionData"'),
    ("/wp-json/wpforms/v1/forms",           "WPForms form definitions",                         "low",    '"id"'),
    ("/wp-json/yoast/v1/configuration",     "Yoast SEO config",                                 "low",    '"yoast"'),
    ("/wp-json/elementor/v1/site-info",     "Elementor site info",                              "low",    '"name"'),
    ("/?rest_route=/wp/v2/settings",        "Settings via legacy ?rest_route= variant",         "high",   '"title"'),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    discovered_namespaces: list[str] = []
    exposed: list[tuple[str, str, str]] = []  # (endpoint, severity, marker_present?)

    for path, desc, sev, marker in REST_ENDPOINTS:
        step(f"probing REST endpoint {path}...")
        r = await client.get(path)
        if r is None:
            continue
        if r.status_code != 200:
            continue
        body = r.text or ""

        # /wp-json/ root: extract namespaces for context
        if path == "/wp-json/":
            try:
                import json as _json
                data = _json.loads(body)
                discovered_namespaces = list(data.get("namespaces") or [])
            except (ValueError, AttributeError):
                pass

        if marker.lower() in body.lower():
            exposed.append((path, sev, "marker present"))

    if discovered_namespaces:
        findings.append(
            Finding(
                severity="info",
                title=f"WordPress REST API exposes {len(discovered_namespaces)} namespace(s)",
                evidence="Namespaces:\n" + "\n".join(f"  - {n}" for n in sorted(discovered_namespaces)),
                remediation=(
                    "REST namespaces aren't sensitive by themselves but they reveal active plugins. "
                    "Each namespace can be locked down via the rest_endpoints filter if exposure is unwanted."
                ),
                url=client.url("/wp-json/"),
                extra={"namespaces": discovered_namespaces},
            )
        )

    for path, sev, _ in exposed:
        # Skip the root which we already reported with namespaces
        if path == "/wp-json/":
            continue
        # Look up the description
        desc = next((d for p, d, _, _ in REST_ENDPOINTS if p == path), path)
        findings.append(
            Finding(
                severity=sev,
                title=f"Public REST endpoint exposes data: {path}",
                evidence=(
                    f"GET {path} -> 200 with expected content marker present.\n"
                    f"  Endpoint description: {desc}"
                ),
                remediation=(
                    "If you don't need this endpoint publicly, restrict it via the rest_endpoints filter:\n"
                    "  add_filter('rest_endpoints', function($e) {\n"
                    f"      unset($e['{path.replace('/wp-json', '')}']);\n"
                    "      return $e;\n"
                    "  });"
                ),
                url=client.url(path),
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No REST API surface findings",
                evidence=f"Probed {len(REST_ENDPOINTS)} endpoints; none returned exposed data.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
