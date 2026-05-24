"""Round-64 #140 — Prometheus exporter for the WPSecScan daemon.

Scrapes the daemon REST API and exposes metrics on :9876/metrics.

Usage:
    pip install prometheus_client httpx
    WPSECSCAN_DAEMON_URL=http://localhost:8080 python prometheus/exporter.py
"""
from __future__ import annotations

import os
import time
import sys

import httpx

try:
    from prometheus_client import Gauge, start_http_server
except ImportError:
    print("pip install prometheus_client required", file=sys.stderr)
    raise SystemExit(1)


DAEMON_URL = os.environ.get("WPSECSCAN_DAEMON_URL", "http://localhost:8080")
TOKEN = os.environ.get("WPSECSCAN_API_TOKEN", "")
SCRAPE_INTERVAL = int(os.environ.get("SCRAPE_INTERVAL_SECONDS", "60"))


# Metrics
g_critical = Gauge("wpsecscan_findings_critical", "Critical findings, latest scan", ["site"])
g_high     = Gauge("wpsecscan_findings_high",     "High findings, latest scan",     ["site"])
g_medium   = Gauge("wpsecscan_findings_medium",   "Medium findings, latest scan",   ["site"])
g_low      = Gauge("wpsecscan_findings_low",      "Low findings, latest scan",      ["site"])
g_info     = Gauge("wpsecscan_findings_info",     "Info findings, latest scan",     ["site"])
g_total    = Gauge("wpsecscan_findings_total",    "Total findings, latest scan",    ["site"])
g_risk     = Gauge("wpsecscan_risk_score",        "Risk score (0-100)",             ["site"])
g_age      = Gauge("wpsecscan_last_scan_age_seconds", "Age of latest scan in seconds", ["site"])


def _fetch_sites() -> list[dict]:
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    try:
        r = httpx.get(f"{DAEMON_URL.rstrip('/')}/sites", headers=headers, timeout=15.0)
        r.raise_for_status()
        return r.json().get("sites", [])
    except (httpx.HTTPError, ValueError):
        return []


def _fetch_latest_for_site(site_id: str) -> dict | None:
    headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
    try:
        r = httpx.get(f"{DAEMON_URL.rstrip('/')}/sites/{site_id}/latest-scan", headers=headers, timeout=15.0)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def update_metrics() -> None:
    sites = _fetch_sites()
    for site in sites:
        sid = site.get("id") or site.get("name") or "unknown"
        scan = _fetch_latest_for_site(sid)
        if not scan:
            continue
        s = scan.get("summary", {}) or {}
        labels = {"site": sid}
        g_critical.labels(**labels).set(int(s.get("critical", 0)))
        g_high    .labels(**labels).set(int(s.get("high", 0)))
        g_medium  .labels(**labels).set(int(s.get("medium", 0)))
        g_low     .labels(**labels).set(int(s.get("low", 0)))
        g_info    .labels(**labels).set(int(s.get("info", 0)))
        g_total   .labels(**labels).set(sum(int(s.get(k, 0)) for k in ("critical", "high", "medium", "low", "info")))
        if "risk_score" in scan:
            g_risk.labels(**labels).set(float(scan["risk_score"]))
        scanned_at = scan.get("scanned_at")
        if scanned_at:
            try:
                from datetime import datetime, timezone
                ts = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).timestamp()
                g_age.labels(**labels).set(time.time() - ts)
            except ValueError:
                pass


def main() -> None:
    port = int(os.environ.get("PORT", "9876"))
    start_http_server(port)
    print(f"WPSecScan Prometheus exporter listening on :{port}", file=sys.stderr)
    while True:
        update_metrics()
        time.sleep(SCRAPE_INTERVAL)


if __name__ == "__main__":  # pragma: no cover
    main()
