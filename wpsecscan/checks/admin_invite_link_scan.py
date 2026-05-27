"""A33 (v2.6.0) — Discord / Slack invite leak.

Compromised WP installs sometimes have a Slack/Discord/Telegram invite
embedded in an admin notice or sticky post — a back-channel the
attacker uses to push commands to an automated agent (or to recruit
the operator's customers into a phishing community).

Passive: scan the homepage + sitemap-listed posts (limited to first
20) for known invite URL patterns.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_INVITE_PATTERNS = (
    (re.compile(r"discord\.gg/[A-Za-z0-9-]{4,32}"), "Discord"),
    (re.compile(r"discord\.com/invite/[A-Za-z0-9-]{4,32}"), "Discord"),
    (re.compile(r"join\.slack\.com/t/[\w-]+/shared_invite/[\w./-]+"), "Slack"),
    (re.compile(r"t\.me/joinchat/[A-Za-z0-9_-]{16,}"), "Telegram"),
    (re.compile(r"t\.me/\+[A-Za-z0-9_-]{8,}"), "Telegram"),
    (re.compile(r"chat\.whatsapp\.com/[A-Za-z0-9]{15,}"), "WhatsApp"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    invites: list[tuple[str, str, str]] = []  # (platform, url, found_at)
    for path in ("/", "/wp-login.php", "/?p=1"):
        step(f"invite scan: {path}")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for rx, platform in _INVITE_PATTERNS:
            for m in rx.finditer(r.text):
                invites.append((platform, m.group(0), path))

    if not invites:
        return findings

    findings.append(Finding(
        severity="low",
        title=f"{len(invites)} chat-invite link(s) embedded in public pages",
        evidence=(
            "Invite links found:\n  "
            + "\n  ".join(f"[{p}] {url} (on {at})" for p, url, at in invites[:20])
            + ("\n  ..." if len(invites) > 20 else "")
        ),
        remediation=(
            "1. Confirm each link is intentional (community page, support).\n"
            "2. If unexpected: TREAT AS COMPROMISE. Chat invites embedded\n"
            "   without operator knowledge are a backdoor / phishing channel.\n"
            "3. Search wp_options, wp_posts, and wp_postmeta for the invite\n"
            "   URLs; the entry point is whichever table contains them."
        ),
        url=client.url("/"),
        extra={"invites": [{"platform": p, "url": u} for p, u, _ in invites]},
    ))
    return findings
