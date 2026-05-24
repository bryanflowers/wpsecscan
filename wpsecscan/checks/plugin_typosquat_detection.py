"""Plugin typosquat detection — compare installed slugs vs top wp.org names.

Round-64 #58 — attackers publish plugins with names one or two
characters away from a popular plugin ("yost-seo" vs "yoast-seo") hoping
admins install the wrong one. We compare each installed-plugin slug
against a curated top-50 wp.org list using Levenshtein distance, and
flag any near-but-not-exact match.
"""
from __future__ import annotations


from ..http import Client
from ..models import Finding

# Top WP plugins by active-install count (curated; refresh manually each
# major release). Compared against actually-installed slugs.
_TOP_PLUGINS = (
    "yoast-seo", "wordpress-seo", "contact-form-7", "elementor", "akismet",
    "jetpack", "wpforms", "wpforms-lite", "wordfence", "all-in-one-seo-pack",
    "google-site-kit", "google-analytics-for-wordpress", "monsterinsights",
    "woocommerce", "wp-rocket", "wp-super-cache", "w3-total-cache",
    "litespeed-cache", "really-simple-ssl", "limit-login-attempts-reloaded",
    "redirection", "duplicator", "updraftplus", "all-in-one-wp-migration",
    "loginizer", "antispam-bee", "advanced-custom-fields", "acf-pro",
    "classic-editor", "tinymce-advanced", "smush", "ewww-image-optimizer",
    "imagify", "shortpixel-image-optimiser", "wpfastestcache",
    "broken-link-checker", "wp-mail-smtp", "post-smtp", "easy-wp-smtp",
    "elementskit-lite", "essential-addons-for-elementor-lite",
    "premium-addons-for-elementor", "happy-elementor-addons",
    "metform", "user-registration", "profile-builder", "polylang",
    "wpml", "translatepress-multilingual", "weglot", "loco-translate",
)


def _levenshtein(a: str, b: str) -> int:
    """Standard Levenshtein distance. Bounded len keeps the cost trivial."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Iterative DP; both inputs are short slugs.
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(
                prev[j] + 1,
                cur[j - 1] + 1,
                prev[j - 1] + (0 if ca == cb else 1),
            )
        prev = cur
    return prev[-1]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Get the already-detected plugin list from shared context (populated by plugins.py)
    shared = ctx.get("shared", {}) or {}
    installed = shared.get("plugins") or shared.get("plugin_slugs") or []
    # Fallback: extract from raw plugin findings
    if not installed:
        return findings

    # Normalise to slugs only
    slugs = []
    for p in installed:
        if isinstance(p, str):
            slugs.append(p)
        elif isinstance(p, dict):
            s = p.get("slug") or p.get("name")
            if s:
                slugs.append(s)

    step(f"comparing {len(slugs)} installed plugin slug(s) vs top-{len(_TOP_PLUGINS)} known list...")

    typosquat_hits: list[tuple[str, str, int]] = []
    top_set = set(_TOP_PLUGINS)
    for s in slugs:
        s_clean = s.lower().strip()
        if s_clean in top_set:
            continue  # Exact match — not a typosquat
        # Find closest top plugin within Levenshtein distance 1 or 2
        for top in _TOP_PLUGINS:
            if abs(len(top) - len(s_clean)) > 2:
                continue
            d = _levenshtein(s_clean, top)
            if 1 <= d <= 2:
                typosquat_hits.append((s_clean, top, d))
                break

    for installed_slug, looks_like, distance in typosquat_hits:
        findings.append(
            Finding(
                severity="high",
                title=f"Possible plugin typosquat: {installed_slug} vs {looks_like}",
                evidence=f"Installed: {installed_slug!r}\n  Looks like top-plugin: {looks_like!r}\n  Levenshtein distance: {distance}",
                remediation=(
                    f"Verify the installed plugin {installed_slug!r} is what you intended.\n"
                    f"Typosquat plugins often bundle the legitimate plugin's functionality PLUS a backdoor.\n"
                    f"If you meant to install {looks_like!r}, uninstall the typosquat first, then install the canonical wp.org version."
                ),
                url=client.url(f"/wp-content/plugins/{installed_slug}/"),
                extra={"installed": installed_slug, "looks_like": looks_like, "distance": distance},
            )
        )

    return findings
