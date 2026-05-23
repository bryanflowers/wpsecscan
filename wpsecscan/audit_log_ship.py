"""M37 Audit-log shipping (Splunk HEC / Datadog / Loki).

After every scan, ship the audit-log entry (already written by audit_log.py)
to a remote SIEM. Three protocols supported, picked by URL prefix:

  - Splunk HEC:    https://<host>/services/collector/event   (Authorization: Splunk <token>)
  - Loki:          https://<host>/loki/api/v1/push           (no auth or basic)
  - Datadog Logs:  https://http-intake.logs.datadoghq.com/api/v2/logs (DD-API-KEY header)

Configure via env:
  WPSECSCAN_AUDIT_SHIP_URL=...      (the endpoint)
  WPSECSCAN_AUDIT_SHIP_TOKEN=...    (the auth token)

Failures are silent (so SIEM downtime doesn't break a scan); they're logged
once to the audit log itself with `ship_failed=True`.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from urllib.error import HTTPError, URLError


def _detect_protocol(url: str) -> str:
    """Match against URL features in most-specific-first order.

    Datadog is checked before Loki because a custom Datadog host that happens
    to contain "loki" anywhere would otherwise mis-route to the Loki payload
    shape and be silently dropped on the Datadog ingest side.
    """
    u = url.lower()
    if "/services/collector" in u:
        return "splunk"
    if "datadog" in u or "datadoghq" in u:
        return "datadog"
    if "/loki/api" in u or u.endswith("/loki") or "/loki/" in u:
        return "loki"
    return "generic"


def _build_request(url: str, token: str, payload: dict):
    proto = _detect_protocol(url)
    headers = {"Content-Type": "application/json", "User-Agent": "WPSecScan/audit_ship"}
    if proto == "splunk":
        headers["Authorization"] = f"Splunk {token}"
        body = json.dumps({"event": payload, "sourcetype": "wpsecscan:scan"})
    elif proto == "loki":
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = json.dumps({
            "streams": [{
                "stream": {"app": "wpsecscan", "event": payload.get("event", "scan")},
                "values": [[str(int(time.time() * 1e9)),
                            json.dumps(payload)]],
            }],
        })
    elif proto == "datadog":
        headers["DD-API-KEY"] = token
        body = json.dumps([{**payload, "ddsource": "wpsecscan", "service": "wpsecscan"}])
    else:
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = json.dumps(payload)
    return urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")


def ship(payload: dict, *, timeout: float = 3.0) -> bool:
    """Ship one audit-log record. Returns True on success, False otherwise.
    Silent on failure — never raises."""
    url = os.environ.get("WPSECSCAN_AUDIT_SHIP_URL", "").strip()
    token = os.environ.get("WPSECSCAN_AUDIT_SHIP_TOKEN", "").strip()
    if not url:
        return False
    proto = _detect_protocol(url)
    try:
        req = _build_request(url, token, payload)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ok = 200 <= resp.status < 300
    except (HTTPError, URLError, OSError):
        ok = False
    try:
        from . import activity as _act
        _act.emit("integration", f"audit log → {proto} ({'ok' if ok else 'fail'})")
    except ImportError:
        pass
    return ok
