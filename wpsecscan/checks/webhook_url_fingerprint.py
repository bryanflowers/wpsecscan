"""Webhook URL fingerprint — flag Discord/Slack/Telegram outbound URLs.

Round-64 #65 — many WP plugins let admins paste a Discord/Slack/
Telegram webhook URL for notifications. These URLs are themselves
credentials (anyone with the URL can post to that channel). The
companion plugin exposes /wp-json/wpsecscan-companion/v1/webhooks
returning [{option_key, url}]. We flag any that match known webhook
hostnames so admins can audit + rotate them.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Each entry: (host-regex, service-name, severity, why)
_WEBHOOK_HOSTS = (
    (re.compile(r"discord\.com/api/webhooks/", re.IGNORECASE),
     "Discord", "medium", "Discord webhook URLs are credentials — anyone with the URL can post"),
    (re.compile(r"hooks\.slack\.com/services/", re.IGNORECASE),
     "Slack", "medium", "Slack webhook URLs are credentials"),
    (re.compile(r"api\.telegram\.org/bot[0-9]+:", re.IGNORECASE),
     "Telegram", "high", "Telegram bot tokens are full bot credentials — leak = full account compromise"),
    (re.compile(r"hooks\.zapier\.com/hooks/catch/", re.IGNORECASE),
     "Zapier", "low", "Zapier webhooks can trigger arbitrary downstream workflows"),
    (re.compile(r"webhook\.site/", re.IGNORECASE),
     "webhook.site", "high", "webhook.site is a debugging service — a real prod site should NEVER post to it"),
    (re.compile(r"hooks\.azure\.com/", re.IGNORECASE),
     "Azure", "medium", "Azure webhook URL"),
    (re.compile(r"events\.pagerduty\.com/v2/", re.IGNORECASE),
     "PagerDuty", "low", "PagerDuty events API — leak = noise but not pivot"),
    (re.compile(r"api\.mailgun\.net", re.IGNORECASE),
     "Mailgun", "medium", "Mailgun API URL — may include API key"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("querying companion plugin for webhook URLs...")
    r = await client.get("/wp-json/wpsecscan-companion/v1/webhooks")
    if r is None or r.status_code == 404:
        return findings
    if r.status_code != 200:
        return findings

    try:
        data = r.json()
    except (ValueError, TypeError):
        return findings

    webhooks = data.get("webhooks", []) if isinstance(data, dict) else []

    for w in webhooks:
        if not isinstance(w, dict):
            continue
        url = str(w.get("url", ""))
        option = w.get("option_key", "?")
        if not url:
            continue
        for pat, service, sev, why in _WEBHOOK_HOSTS:
            if pat.search(url):
                # Mask the actual URL — don't include the full secret in evidence
                masked = url[:30] + "..." + url[-10:] if len(url) > 50 else url
                findings.append(
                    Finding(
                        severity=sev,
                        title=f"{service} webhook configured in option {option}",
                        evidence=f"Option {option!r} contains a {service} webhook URL.\n  Masked: {masked!r}\n  {why}",
                        remediation=(
                            f"Document this {service} integration in your secret-registry.\n"
                            f"Rotate the webhook URL if you suspect leak (anyone who has read the WP DB or wp_options table has the URL).\n"
                            f"Consider moving the URL into a wp-config.php constant or env-var instead of wp_options."
                        ),
                        url=client.url("/wp-admin/options.php"),
                        extra={"option_key": option, "service": service},
                    )
                )
                break

    return findings
