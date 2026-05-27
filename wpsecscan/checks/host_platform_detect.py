"""N136 + N139 + N140 (v2.6.0) — host / stack fingerprint with
platform-specific advisories.

Detects:
  • Roots stack (Bedrock / Sage / Trellis / Sail)
  • WordPress VIP (Go)
  • WP Engine, Kinsta, Pantheon, Cloudways

For each detected host, emits an info-level "platform detected" entry
plus host-specific medium advisories where one applies (e.g. WP-VIP
enforces some controls in its own ingress that other hosts don't;
operators sometimes layer duplicate / conflicting protections on top).
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


# (header-name, header-substring-match, platform-name)
_HEADER_SIGS = (
    ("server", "wpe", "WP Engine"),
    ("server", "wpengine", "WP Engine"),
    ("server", "x-cache-handler", "WP Engine"),
    ("x-pantheon-styx-hostname", "", "Pantheon"),
    ("server", "kinsta", "Kinsta"),
    ("x-kinsta-cache", "", "Kinsta"),
    ("server", "cloudways", "Cloudways"),
    ("x-cf-server", "vip", "WordPress VIP"),
    ("x-served-by", "varnish-vip", "WordPress VIP"),
    ("x-platform", "wpvip", "WordPress VIP"),
)

# Body / path fingerprints (Roots stack)
_BEDROCK_PATHS = (
    "/wp/wp-login.php",   # Bedrock moves WP core to /wp/
    "/app/themes/",       # Bedrock content dir
    "/app/plugins/",
)


def _platform_advisory(platform: str) -> tuple[str, str, str]:
    """Return (severity, title-suffix, remediation-paragraph)."""
    if platform == "WP Engine":
        return ("medium",
                "host-specific: WP Engine ignores .htaccess",
                "WP Engine uses nginx; .htaccess rules are silently ignored. "
                "Verify any security-header config is at the Application → "
                "Settings → Redirect Rules level OR via wp-config.php / a "
                "must-use plugin. Existing .htaccess deny-rules give a false "
                "sense of protection here.")
    if platform == "Kinsta":
        return ("medium",
                "host-specific: Kinsta nginx + Cloudflare Enterprise WAF",
                "Kinsta sits behind Cloudflare Enterprise; many checks the "
                "scanner runs will be intercepted before reaching the origin. "
                "Verify the operator runs the scan with the Kinsta-issued "
                "IP-allow-list header (X-Kinsta-Allow) if testing the origin "
                "directly. WAF auto-derate is already on by default in "
                "wpsecscan.")
    if platform == "Pantheon":
        return ("medium",
                "host-specific: Pantheon enforces multidev env URLs",
                "Pantheon serves dev/test/live environments on separate URLs "
                "(dev-, test-, live-). Audit whether dev/test environments "
                "are publicly accessible (they often are, with the same DB "
                "as production). Restrict via Pantheon's HTTP Basic Auth or "
                "lock_environment.")
    if platform == "Cloudways":
        return ("low",
                "host-specific: Cloudways platform",
                "Cloudways exposes a separate Platform API (api.cloudways.com) "
                "for server management. Confirm the operator's Platform-API "
                "key is rotated quarterly + scoped per-application.")
    if platform == "WordPress VIP":
        return ("info",
                "host-specific: WordPress VIP",
                "VIP Go enforces 2FA-required, IP allow-list for SSH, and "
                "automatic plugin-update review. Several checks the scanner "
                "runs (XML-RPC, weak-cipher TLS, missing security headers) "
                "are platform-managed on VIP and may safely be policy-suppressed "
                "via ~/.wpsecscan/policy.yml if the operator confirms they're "
                "VIP-managed.")
    return ("", "", "")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    detected: set[str] = set()

    # Header-based fingerprints from homepage
    step("host platform: GET / + inspect headers")
    home = await client.get("/")
    if home is not None:
        for hdr, sub, name in _HEADER_SIGS:
            v = home.headers.get(hdr, "").lower()
            if sub and sub.lower() in v:
                detected.add(name)
            elif not sub and v:
                detected.add(name)

    # Bedrock / Roots paths
    step("host platform: Bedrock /wp/wp-login.php probe")
    bd = await client.get("/wp/wp-login.php", follow_redirects=False)
    if bd is not None and bd.status_code in (200, 302, 403):
        body = (bd.text or "")[:300].lower() if bd.text else ""
        if "wordpress" in body or bd.status_code == 302:
            detected.add("Bedrock (Roots)")

    # Roots Sage in body (theme functions)
    if home is not None and home.text:
        if "/app/themes/" in home.text or "wp-content/themes/sage" in home.text.lower():
            detected.add("Roots Sage")
        if "/app/uploads/" in home.text:
            detected.add("Bedrock (Roots)")

    if not detected:
        return findings

    for platform in sorted(detected):
        findings.append(Finding(
            severity="info",
            title=f"Host / stack detected: {platform}",
            evidence=(
                f"Platform fingerprint: {platform}.\n"
                "wpsecscan's check defaults are tuned for vanilla shared-hosting "
                "WordPress; host-specific advice follows."
            ),
            remediation=(
                "Confirm the platform-managed controls and suppress duplicate "
                "checks in ~/.wpsecscan/policy.yml if appropriate."
            ),
            url=str(client.base_url),
            extra={"platform": platform},
        ))
        sev, suffix, rem = _platform_advisory(platform)
        if sev:
            findings.append(Finding(
                severity=sev,
                title=f"{platform} {suffix}",
                evidence=f"Platform: {platform}.\n{rem.splitlines()[0]}",
                remediation=rem,
                url=str(client.base_url),
                extra={"platform": platform, "category": "host-specific"},
            ))
    return findings
