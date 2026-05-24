"""Round-64 #138 — Datadog Agent custom check.

Drop into /etc/datadog-agent/checks.d/wpsecscan.py + drop the conf.d
YAML below alongside it. Reports the last scan's severity counts as
metrics + emits a service check based on the worst severity.

conf.d/wpsecscan.yaml:
    init_config: {}
    instances:
      - daemon_url: http://localhost:8080
        api_token: ...
        tags:
          - env:prod
"""
from datadog_checks.base import AgentCheck, ConfigurationError  # type: ignore
import requests


class WPSecScanCheck(AgentCheck):
    SERVICE_CHECK_NAME = "wpsecscan.scan_health"

    def check(self, instance):
        url = instance.get("daemon_url")
        if not url:
            raise ConfigurationError("daemon_url is required")
        token = instance.get("api_token", "")
        tags = list(instance.get("tags", []))

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            r = requests.get(f"{url.rstrip('/')}/scans/latest", headers=headers, timeout=15)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL, tags=tags, message=str(e))
            return

        summary = data.get("summary", {}) or {}
        for sev in ("critical", "high", "medium", "low", "info"):
            self.gauge(f"wpsecscan.findings.{sev}", int(summary.get(sev, 0)), tags=tags)

        # Service check status from worst severity
        if int(summary.get("critical", 0)) > 0:
            status = AgentCheck.CRITICAL
            msg = f"{summary['critical']} critical findings"
        elif int(summary.get("high", 0)) > 0:
            status = AgentCheck.WARNING
            msg = f"{summary['high']} high-severity findings"
        else:
            status = AgentCheck.OK
            msg = "No urgent findings"
        self.service_check(self.SERVICE_CHECK_NAME, status, tags=tags, message=msg)

        # Risk score gauge (if exposed)
        if "risk_score" in data:
            self.gauge("wpsecscan.risk_score", float(data["risk_score"]), tags=tags)
