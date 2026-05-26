from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

EMOJI_VER_RE = re.compile(r"wp-emoji-release\.min\.js\?ver=([0-9.]+)", re.IGNORECASE)

# High-confidence markers: any of these alone is a strong PHP-error signal.
HIGH_CONF_PHP_MARKERS = (
    "Fatal error",
    "Stack trace:",
    "Uncaught Error",
    "Uncaught Exception",
)

# Low-confidence markers: "on line", "Warning:", "Notice:" etc. appear in
# legitimate page content (poetry, legal text, recipes). Only fire when they
# co-occur in adjacent contexts that look like an actual PHP error line, e.g.
# "Warning: X in /home/user/file.php on line 42".
PHP_ERROR_LINE_RE = re.compile(
    r"(?:Warning|Notice|Deprecated|Strict standards)\s*:\s*.+?\s+in\s+/(?:home|var|usr|opt)/\S+\.\S+\s+on\s+line\s+\d+",
    re.IGNORECASE,
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # 1. debug.log readable?
    step("probing /wp-content/debug.log...")
    dl = await client.get("/wp-content/debug.log")
    if dl is not None and dl.status_code == 200 and dl.text:
        body = dl.text
        if any(m in body for m in ("PHP", "WordPress", "Stack trace", "Notice:", "Warning:", "Fatal")):
            preview = "\n".join(body.splitlines()[:5])
            findings.append(
                Finding(
                    severity="high",
                    title="/wp-content/debug.log is publicly readable",
                    evidence=f"GET /wp-content/debug.log → 200; first lines:\n{preview}",
                    remediation=(
                        "Block /wp-content/debug.log at the server, and set "
                        "`define('WP_DEBUG_LOG', '/path/outside/docroot/debug.log');` so logs never live under the docroot. "
                        "In production, also set `WP_DEBUG_DISPLAY` to false."
                    ),
                    url=client.url("/wp-content/debug.log"),
                )
            )

    # 2. Triggered error → check for stack traces in 500-ish responses
    weird = await client.get("/?p[]=1")
    if weird is not None and weird.status_code in (200, 500) and weird.text:
        text = weird.text
        # Fire on either:
        #   - any HIGH_CONF marker present (these are PHP-specific phrases that
        #     don't appear in legitimate content), OR
        #   - a full PHP error line shape (Warning/Notice + "in /path/file" +
        #     "on line N"). Previously bare "Warning:" or "on line" matches
        #     fired on disclaimers, poetry, and recipe pages.
        high_conf_hits = [m for m in HIGH_CONF_PHP_MARKERS if m in text]
        error_line_hits = PHP_ERROR_LINE_RE.findall(text)
        if high_conf_hits or error_line_hits or weird.status_code == 500:
            preview_lines: list[str] = []
            if high_conf_hits:
                preview_lines.extend(
                    [l for l in text.splitlines() if any(m in l for m in HIGH_CONF_PHP_MARKERS)][:3]
                )
            if error_line_hits:
                preview_lines.extend(error_line_hits[:3])
            preview = "\n".join(preview_lines) or f"HTTP {weird.status_code} on /?p[]=1"
            findings.append(
                Finding(
                    severity="medium",
                    title="PHP error / stack trace leaks via crafted query",
                    evidence=f"GET /?p[]=1 → response contains PHP error markers:\n{preview}",
                    remediation=(
                        "In wp-config.php: set `WP_DEBUG_DISPLAY` to false and `display_errors` to Off in php.ini. "
                        "Errors should go to a log file, never the response body."
                    ),
                    url=client.url("/?p[]=1"),
                )
            )

    # 3. Emoji script reveals WP version (cosmetic but a fingerprint vector)
    home = await client.get("/")
    if home is not None and home.text:
        m = EMOJI_VER_RE.search(home.text)
        if m:
            findings.append(
                Finding(
                    severity="low",
                    title=f"wp-emoji-release.min.js exposes WP version via ?ver= ({m.group(1)})",
                    evidence=f"Found `wp-emoji-release.min.js?ver={m.group(1)}` in homepage.",
                    remediation=(
                        "Disable the emoji feature (it's rarely useful): "
                        "`remove_action('wp_head','print_emoji_detection_script', 7);` and the related actions. "
                        "Or strip ?ver= from all asset URLs via a filter."
                    ),
                    url=ctx["target"],
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No debug / info leaks detected",
                evidence="debug.log not readable, no stack traces from crafted query, no emoji version fingerprint.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
