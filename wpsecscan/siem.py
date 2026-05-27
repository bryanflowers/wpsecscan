"""Item #61 — live SIEM forwarders.

Streams findings as discrete events to a SIEM intake URL, on top of the
existing JSON-file output. Today's supported backends:

  Splunk HEC     — POST to /services/collector with `Authorization: Splunk <token>`
  Datadog Logs   — POST to /api/v2/logs with `DD-API-KEY: <key>`
  Grafana Loki   — POST to /loki/api/v1/push (label-based)
  Elastic Beats  — POST to a Logstash HTTP input (port 9600 default)

Each emits *one event per finding* (not one event per scan) so a SIEM
correlation engine can alert on individual high/critical detections.

Failures are non-fatal: the function logs to stderr and returns 0/1 so
the caller can keep going. We never block the scan output on the SIEM.
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from .models import ScanReport


_USER_AGENT = "WPSecScan-SIEM/1.0"

# S10: redact anything in an error message that looks like a long
# opaque token before it bubbles to the console. Splunk HEC tokens,
# Datadog API keys, and JWTs all match this pattern. Conservative: we
# only redact strings of 24+ chars that are pure base64url / hex —
# normal English text and URLs are safe.
import re as _re
# Match long opaque tokens AND JWT-style three-part tokens (header.payload.sig)
# where any of the three parts is itself long. \b word boundaries don't span
# `.`, so JWTs need their own alternation.
_TOKEN_RE = _re.compile(
    r"(?:[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"  # JWT
    r"|"
    r"\b[A-Za-z0-9+/=_-]{24,}\b"                                     # long opaque blob
)


def _redact(msg: str) -> str:
    """Mask token-shaped substrings in an SIEM-forwarder error message."""
    return _TOKEN_RE.sub("[redacted-token]", msg)


def _build_events(report: ScanReport, source: str) -> list[dict[str, Any]]:
    """Flatten the report into one dict per finding for SIEM ingest."""
    events: list[dict[str, Any]] = []
    for r in report.results:
        for f in r.findings:
            events.append({
                "timestamp": report.scanned_at,
                "source": source,
                "target": report.target,
                "check_id": r.check_id,
                "check_name": r.check_name,
                "severity": f.severity,
                "title": f.title,
                "evidence": (f.evidence or "")[:2000],
                "remediation": (f.remediation or "")[:1000],
                "url": f.url or "",
                "risk_score": report.risk_score,
                "scanner": "wpsecscan",
            })
    return events


def post_splunk_hec(report: ScanReport, hec_url: str, token: str,
                    *, source: str = "wpsecscan", verify: bool = True,
                    timeout: float = 10.0) -> tuple[int, str]:
    """Forward every finding to Splunk HEC. Returns (sent_count, message)."""
    events = _build_events(report, source)
    if not events:
        return 0, "no findings to forward"
    # Splunk HEC accepts one event per line, no commas between objects.
    payload = "\n".join(json.dumps({
        "event": ev,
        "sourcetype": "_json",
        "source": source,
        "host": urlparse(report.target).hostname or report.target,
        "time": int(time.time()),
    }) for ev in events)
    try:
        with httpx.Client(verify=verify, timeout=timeout,
                           headers={"User-Agent": _USER_AGENT}) as c:
            r = c.post(hec_url.rstrip("/") + "/services/collector",
                        headers={"Authorization": f"Splunk {token}"},
                        content=payload)
            if r.status_code >= 400:
                return 0, _redact(f"splunk HEC {r.status_code}: {r.text[:200]}")
            return len(events), f"splunk HEC accepted {len(events)} event(s)"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return 0, _redact(f"splunk HEC error: {e}")


def post_datadog_logs(report: ScanReport, api_key: str,
                       *, intake: str = "https://http-intake.logs.datadoghq.com",
                       service: str = "wpsecscan",
                       tags: str | None = None,
                       timeout: float = 10.0) -> tuple[int, str]:
    """Forward every finding to the Datadog Logs HTTP intake.

    `intake` defaults to the US site; pass the EU equivalent (`.eu`) etc.
    if your org's tenant is on another region.
    """
    events = _build_events(report, service)
    if not events:
        return 0, "no findings to forward"
    payload = []
    for ev in events:
        payload.append({
            "ddsource": "wpsecscan",
            "ddtags": tags or f"target:{urlparse(report.target).hostname},severity:{ev['severity']}",
            "hostname": urlparse(report.target).hostname or "wpsecscan",
            "message": json.dumps(ev),
            "service": service,
        })
    try:
        with httpx.Client(timeout=timeout,
                           headers={"User-Agent": _USER_AGENT,
                                    "DD-API-KEY": api_key,
                                    "Content-Type": "application/json"}) as c:
            r = c.post(intake.rstrip("/") + "/api/v2/logs",
                        content=json.dumps(payload))
            if r.status_code >= 400:
                return 0, _redact(f"datadog {r.status_code}: {r.text[:200]}")
            return len(events), f"datadog accepted {len(events)} log entr(ies)"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return 0, _redact(f"datadog error: {e}")


def post_loki(report: ScanReport, push_url: str,
               *, job: str = "wpsecscan",
               tenant: str | None = None,
               timeout: float = 10.0) -> tuple[int, str]:
    """Forward every finding to a Grafana Loki push endpoint.

    `push_url` is typically `https://logs-XX.grafana.net/loki/api/v1/push`
    (Grafana Cloud) or `http://loki:3100/loki/api/v1/push` (self-hosted).
    Tenant header is only needed on multi-tenant Loki (e.g. Cortex/Mimir).
    """
    events = _build_events(report, job)
    if not events:
        return 0, "no findings to forward"
    streams: dict[tuple, list[list[str]]] = {}
    now_ns = str(int(time.time() * 1_000_000_000))
    host = urlparse(report.target).hostname or report.target
    for ev in events:
        key = (("job", job), ("target", host), ("severity", ev["severity"]),
                ("check_id", ev["check_id"]))
        streams.setdefault(key, []).append([now_ns, json.dumps(ev)])

    payload = {"streams": [
        {"stream": dict(labels), "values": values}
        for labels, values in streams.items()
    ]}
    headers = {"User-Agent": _USER_AGENT, "Content-Type": "application/json"}
    if tenant:
        headers["X-Scope-OrgID"] = tenant
    try:
        with httpx.Client(timeout=timeout, headers=headers) as c:
            r = c.post(push_url, content=json.dumps(payload))
            if r.status_code >= 400:
                return 0, _redact(f"loki {r.status_code}: {r.text[:200]}")
            return len(events), f"loki accepted {len(events)} entr(ies) across {len(streams)} stream(s)"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return 0, _redact(f"loki error: {e}")


def post_beats(report: ScanReport, http_input_url: str,
                *, timeout: float = 10.0) -> tuple[int, str]:
    """Forward every finding to an Elastic Logstash HTTP input.

    Logstash's `http` input accepts JSON arrays out of the box; this is a
    lighter-weight alternative to running Filebeat. URL is typically
    `http://logstash:8080`.
    """
    events = _build_events(report, "wpsecscan")
    if not events:
        return 0, "no findings to forward"
    try:
        with httpx.Client(timeout=timeout,
                           headers={"User-Agent": _USER_AGENT,
                                    "Content-Type": "application/json"}) as c:
            r = c.post(http_input_url, content=json.dumps(events))
            if r.status_code >= 400:
                return 0, _redact(f"beats/logstash {r.status_code}: {r.text[:200]}")
            return len(events), f"logstash accepted {len(events)} event(s)"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return 0, _redact(f"beats/logstash error: {e}")


def forward_all(report: ScanReport, args) -> list[str]:
    """Driver invoked from __main__. Reads every --siem-* flag (and the
    matching env-var fallbacks) and forwards. Returns human-readable
    status messages so the caller can render them in the console.
    """
    import os
    msgs: list[str] = []

    splunk_url = getattr(args, "siem_splunk", None) or os.environ.get("WPSECSCAN_SPLUNK_HEC")
    splunk_token = getattr(args, "siem_splunk_token", None) or os.environ.get("WPSECSCAN_SPLUNK_TOKEN")
    if splunk_url and splunk_token:
        sent, msg = post_splunk_hec(report, splunk_url, splunk_token)
        msgs.append(f"[splunk] {msg}")

    dd_key = getattr(args, "siem_datadog", None) or os.environ.get("WPSECSCAN_DATADOG_API_KEY")
    if dd_key:
        intake = os.environ.get("WPSECSCAN_DATADOG_INTAKE",
                                 "https://http-intake.logs.datadoghq.com")
        sent, msg = post_datadog_logs(report, dd_key, intake=intake)
        msgs.append(f"[datadog] {msg}")

    loki_url = getattr(args, "siem_loki", None) or os.environ.get("WPSECSCAN_LOKI_URL")
    if loki_url:
        tenant = os.environ.get("WPSECSCAN_LOKI_TENANT")
        sent, msg = post_loki(report, loki_url, tenant=tenant)
        msgs.append(f"[loki] {msg}")

    beats_url = getattr(args, "siem_beats", None) or os.environ.get("WPSECSCAN_BEATS_URL")
    if beats_url:
        sent, msg = post_beats(report, beats_url)
        msgs.append(f"[beats] {msg}")

    return msgs
