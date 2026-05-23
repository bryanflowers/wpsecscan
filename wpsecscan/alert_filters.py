"""#28 (from ZAP) — alert filters: hide / re-rank known findings.

A filter file at ~/.wpsecscan/alert_filters.json says "this finding is
a known issue / accepted risk — hide it or downgrade severity in
reports". Example:

    {
      "filters": [
        {
          "match": {"check_id": "tls_headers", "title_contains": "HSTS"},
          "action": "downgrade",
          "to": "info",
          "reason": "We use Cloudflare's Strict-Transport-Security at the edge."
        },
        {
          "match": {"check_id": "dev_params"},
          "action": "hide",
          "reason": "Known dev-toggle param; safe in our setup."
        }
      ]
    }

This module loads the filter file and applies it to a finished
ScanReport. Wired into json_reporter._enrich so saved reports reflect
the filtered view.
"""
from __future__ import annotations

import json
from pathlib import Path


def _filter_path() -> Path:
    from . import history as _h
    return Path(_h._home()) / "alert_filters.json"


def load_filters() -> list[dict]:
    p = _filter_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d.get("filters") or []
    except (OSError, ValueError):
        return []


def _matches(finding, check_id: str, rule: dict) -> bool:
    match = rule.get("match") or {}
    if "check_id" in match and check_id != match["check_id"]:
        return False
    if "severity" in match and finding.severity != match["severity"]:
        return False
    if "title_contains" in match and match["title_contains"] not in (finding.title or ""):
        return False
    if "title_regex" in match:
        import re
        try:
            if not re.search(match["title_regex"], finding.title or ""):
                return False
        except re.error:
            return False
    return True


def apply_to_report(report) -> tuple[int, int]:
    """Apply filters in place. Returns (hidden_count, downgraded_count)."""
    filters = load_filters()
    if not filters:
        return (0, 0)
    hidden = 0
    downgraded = 0
    for r in report.results:
        kept = []
        for f in r.findings:
            action_taken = None
            for rule in filters:
                if not _matches(f, r.check_id, rule):
                    continue
                action = (rule.get("action") or "").lower()
                if action == "hide":
                    action_taken = "hide"
                    break
                if action == "downgrade":
                    new_sev = (rule.get("to") or "info").lower()
                    if new_sev in ("info", "low", "medium", "high", "critical"):
                        f.severity = new_sev
                        action_taken = "downgrade"
                        # Don't `break` — let further rules potentially hide as well
            if action_taken == "hide":
                hidden += 1
                continue
            if action_taken == "downgrade":
                downgraded += 1
            kept.append(f)
        r.findings = kept
    return (hidden, downgraded)
