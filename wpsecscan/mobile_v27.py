"""v2.7.0 mobile / PWA expansion (M131-M135).

  M131 web_push_endpoint(handler)   — Web Push subscription endpoint
                                        used by the mobile_api PWA.
  M132 (template-only)               — PWA dark-mode (prefers-color-scheme +
                                        iOS Safari home-screen theming) —
                                        documented inline in mobile_api INDEX_HTML.
  M133 ios_shortcut_template()       — Shortcuts.app JSON-LD template the
                                        operator pastes.
  M134 watch_complication_json(report) — Apple Watch complication JSON the
                                        operator's companion app reads.
  M135 android_widget_manifest()     — partial Android Web App Manifest
                                        snippet for home-screen widget.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from ._util import home_dir


# ---------------------------------------------------------------------------
# M131 — Web Push registration
# ---------------------------------------------------------------------------

# B19 (v2.8.0) — Web Push endpoints MUST be one of the well-known
# push services. Without this allow-list, a local caller (CLI or
# future REST handler) could register an attacker-controlled HTTPS
# endpoint, and the operator's VAPID-signed payloads (with scan
# details — target URL, finding titles) would be delivered to that
# attacker's server. The list below covers FCM (Chrome/Edge/Opera/
# Firefox+Android), Mozilla autopush (Firefox), Apple WebPush (Safari
# 16+), and Microsoft (Edge legacy). Operators running their own
# push-relay set $WPSECSCAN_WEB_PUSH_EXTRA_HOSTS to extend.
import os as _os_for_push

_WEB_PUSH_ALLOWED_HOSTS = {
    "fcm.googleapis.com",
    "android.googleapis.com",
    "updates.push.services.mozilla.com",
    "autopush.services.mozilla.com",
    "web.push.apple.com",
    "api.push.apple.com",
    "notify.windows.com",
}


def _web_push_endpoint_is_allowed(endpoint: str) -> bool:
    """Return True iff the endpoint is HTTPS and its host is in the
    allow-list (built-in or via $WPSECSCAN_WEB_PUSH_EXTRA_HOSTS)."""
    from urllib.parse import urlparse as _u
    try:
        p = _u(endpoint)
    except (ValueError, AttributeError):
        return False
    if p.scheme != "https" or not p.netloc:
        return False
    host = p.netloc.lower()
    if host in _WEB_PUSH_ALLOWED_HOSTS:
        return True
    extra = (_os_for_push.environ.get("WPSECSCAN_WEB_PUSH_EXTRA_HOSTS") or "").lower()
    extra_set = {h.strip() for h in extra.split(",") if h.strip()}
    return host in extra_set


def web_push_register(endpoint: str, p256dh: str, auth: str) -> str:
    """Register a Web Push subscription. Stored at
    ~/.wpsecscan/web-push-subs.json. The mobile-api server POSTs to
    every saved subscription when a critical finding lands."""
    # B19 (v2.8.0) — refuse subscriptions whose endpoint isn't a
    # recognised push-service origin. Prevents data-exfil via crafted
    # subscription registration.
    if not _web_push_endpoint_is_allowed(endpoint):
        raise ValueError(
            f"refusing web-push registration: endpoint {endpoint!r} is not "
            f"on the allow-list of known push services. Set "
            f"WPSECSCAN_WEB_PUSH_EXTRA_HOSTS=host1,host2 to extend."
        )
    p = home_dir() / "web-push-subs.json"
    try:
        subs = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
    except (OSError, ValueError):
        subs = []
    sid = secrets.token_urlsafe(16)
    subs.append({
        "id": sid,
        "endpoint": endpoint,
        "keys": {"p256dh": p256dh, "auth": auth},
        "added_at": int(__import__("time").time()),
    })
    p.parent.mkdir(parents=True, exist_ok=True)
    # B7 (v2.7.1) — atomic 0o600 write so push-subscription endpoints
    # (which reveal operator's PWA deployment) aren't world-readable.
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(json.dumps(subs, indent=2).encode("utf-8"))
    return sid


def web_push_send(title: str, body: str) -> tuple[int, list[str]]:
    """Send a push notification to every saved subscription. Requires
    pywebpush + VAPID keys at WPSECSCAN_VAPID_PRIVATE_KEY / _CLAIMS_SUB.
    Returns (sent_count, errors)."""
    try:
        from pywebpush import webpush, WebPushException  # type: ignore[import-not-found]
    except ImportError:
        return 0, ["pywebpush not installed: pip install pywebpush"]
    priv = os.environ.get("WPSECSCAN_VAPID_PRIVATE_KEY", "")
    sub = os.environ.get("WPSECSCAN_VAPID_CLAIMS_SUB", "mailto:ops@example.com")
    if not priv:
        return 0, ["set WPSECSCAN_VAPID_PRIVATE_KEY (PEM)"]
    p = home_dir() / "web-push-subs.json"
    if not p.exists():
        return 0, ["no subscriptions registered"]
    try:
        subs = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0, ["malformed subs file"]
    payload = json.dumps({"title": title, "body": body})
    sent = 0
    errors: list[str] = []
    for s in subs:
        try:
            webpush(
                subscription_info={"endpoint": s["endpoint"], "keys": s["keys"]},
                data=payload,
                vapid_private_key=priv,
                vapid_claims={"sub": sub},
            )
            sent += 1
        except WebPushException as e:
            errors.append(str(e)[:200])
    return sent, errors


# ---------------------------------------------------------------------------
# M133 — iOS Shortcut template
# ---------------------------------------------------------------------------

def ios_shortcut_template() -> str:
    """Print a Shortcuts.app `Get Contents of URL` snippet the operator
    can paste into a new Shortcut to trigger a scan from iOS."""
    return (
        "# iOS Shortcut: Trigger WPSecScan\n"
        "Action 1: Text  → enter URL\n"
        "Action 2: URL   → https://YOUR-MOBILE-API-HOST/api/scan\n"
        "Action 3: Get Contents of URL\n"
        "    Method: POST\n"
        "    Headers:\n"
        "      X-WPSecScan-Token: <your token>\n"
        "      Content-Type: application/json\n"
        "    Request Body (JSON):\n"
        "      {\n"
        "        \"target\": \"$(text-from-action-1)\"\n"
        "      }\n"
        "Action 4: Show Result\n"
    )


# ---------------------------------------------------------------------------
# M134 — Apple Watch complication JSON
# ---------------------------------------------------------------------------

def watch_complication_json(report) -> dict:
    """Return the JSON shape the operator's Watch companion polls."""
    s = report.summary
    return {
        "target": report.target,
        "score": report.risk_score,
        "worst": report.worst_severity() or "info",
        "critical": s.get("critical", 0),
        "high": s.get("high", 0),
        "updated_at": report.scanned_at,
    }


# ---------------------------------------------------------------------------
# M135 — Android home-screen widget manifest snippet
# ---------------------------------------------------------------------------

def android_widget_manifest() -> dict:
    """Web App Manifest fragment with shortcuts that materialise as
    home-screen widgets on Android Chrome PWA installs."""
    return {
        "name": "WPSecScan",
        "short_name": "WPSec",
        "display": "standalone",
        "theme_color": "#1f6feb",
        "background_color": "#0d1117",
        "shortcuts": [
            {"name": "Open dashboard", "url": "/",
              "icons": [{"src": "/api/icon-192.png", "sizes": "192x192"}]},
            {"name": "Latest critical", "url": "/?filter=critical",
              "icons": [{"src": "/api/icon-192.png", "sizes": "192x192"}]},
        ],
    }
