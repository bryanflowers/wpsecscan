"""Slack/Discord webhook notify on critical/high findings.

Single POST per scan. The same payload shape works for both Slack incoming
webhooks AND Discord webhooks (Discord ignores Slack's blocks but renders
the `text` field; Slack renders both).
"""
from __future__ import annotations

import ipaddress
import json
import threading
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Slack/Discord webhooks live on specific hosts; we reject everything that
# isn't HTTPS to a hostname (no IPs — prevents accidental sends to AWS metadata
# / file:// / etc. via typo or pasted-from-clipboard mistake).
_ALLOWED_HOST_SUFFIXES = (
    "hooks.slack.com",
    "discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com",
    "webhook.office.com",   # Microsoft Teams
    "events.pagerduty.com",
)


def validate_webhook_url(url: str) -> tuple[bool, str]:
    """Return (ok, reason). Strict allow-list:
      - https only
      - port must be None or 443 (default HTTPS) — no custom ports
      - host must be an exact match against _ALLOWED_HOST_SUFFIXES
        (subdomains are NOT accepted; Slack/Discord/Teams/PagerDuty webhooks
        all live on the apex of these hosts so there's no legitimate need)
      - no raw IPs (covers 169.254.169.254 metadata + loopback typos)
    """
    if not url or not isinstance(url, str):
        return False, "URL is empty"
    url = url.strip()
    try:
        p = urlparse(url)
    except (ValueError, TypeError):
        return False, "URL doesn't parse"
    if p.scheme != "https":
        return False, "Webhook URL must use https:// (got '{}')".format(p.scheme or "no scheme")
    if not p.hostname:
        return False, "URL has no hostname"
    # Reject raw IPs (covers 169.254.169.254 cloud-metadata + file:/// + local-loopback typos)
    try:
        ipaddress.ip_address(p.hostname)
        return False, "Webhook URL must be a hostname, not an IP address"
    except ValueError:
        pass
    # Reject custom ports — only the default HTTPS port (443) is OK.
    # urlparse returns None for "no port specified", which is what we want.
    try:
        port = p.port
    except ValueError:
        return False, "Webhook URL has an invalid port"
    if port is not None and port != 443:
        return False, f"Webhook URL must use port 443 (got {port})"
    # Exact-host allow-list — no subdomain matching. If Slack/Discord/etc.
    # ever start using subdomains for webhooks, add them explicitly.
    host_lc = p.hostname.lower()
    if host_lc not in _ALLOWED_HOST_SUFFIXES:
        return False, (
            f"Host '{p.hostname}' not in webhook allow-list. Allowed: "
            + ", ".join(_ALLOWED_HOST_SUFFIXES)
        )
    return True, ""


def _post_json(url: str, payload: dict, timeout: float = 4.0) -> tuple[bool, str]:
    """POST a JSON body. Returns (ok, error_message)."""
    ok, why = validate_webhook_url(url)
    if not ok:
        return False, why
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "WPSecScan/notify"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if 200 <= resp.status < 300:
                return True, ""
            return False, f"HTTP {resp.status}"
    except HTTPError as e:
        try:
            body = e.read()[:200].decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        return False, f"HTTP {e.code}: {body}"
    except (URLError, OSError, ValueError) as e:
        return False, str(e)


def should_notify(report, threshold: str = "high") -> bool:
    """Return True if the report has at least one finding at or above the threshold."""
    rank_threshold = SEVERITY_RANK.get(threshold, 3)
    for f in report.all_findings:
        if SEVERITY_RANK.get(f.severity, 0) >= rank_threshold:
            return True
    return False


def format_message(report) -> dict:
    """Build a Slack/Discord-friendly payload from a ScanReport."""
    s = report.summary
    score = report.risk_score
    counts = (
        f"{s.get('critical', 0)} critical · {s.get('high', 0)} high · "
        f"{s.get('medium', 0)} medium · {s.get('low', 0)} low · {s.get('info', 0)} info"
    )
    title = f"WPSecScan: {report.target} — score {score}/100"
    body = f"{title}\n{counts}\nScanned: {report.scanned_at}"
    return {"text": body, "username": "WPSecScan"}


def notify(report, webhook_url: str, threshold: str = "high") -> tuple[bool, str]:
    if not webhook_url:
        return False, "no webhook URL"
    if not should_notify(report, threshold):
        return False, f"no findings >= {threshold}"
    return _post_json(webhook_url, format_message(report))


def notify_async(report, webhook_url: str, threshold: str = "high",
                 on_done=None) -> None:
    """Fire-and-forget version: POSTs from a daemon thread so the caller's
    event loop / GUI main thread doesn't block on the webhook.

    on_done(ok: bool, msg: str) is called from the worker thread when done.
    Pass a lambda that schedules its real work on the GUI thread via root.after()."""
    def _worker():
        ok, msg = notify(report, webhook_url, threshold)
        if on_done:
            try:
                on_done(ok, msg)
            except Exception:  # noqa: BLE001
                pass
    t = threading.Thread(target=_worker, daemon=True, name="wpsec-webhook")
    t.start()


def send_test(webhook_url: str) -> tuple[bool, str]:
    """Fire a one-line test message to confirm the webhook works."""
    payload = {"text": "✓ WPSecScan webhook test — your URL is configured correctly.",
               "username": "WPSecScan"}
    return _post_json(webhook_url, payload)
