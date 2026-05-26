"""Items #40 + #41 — per-site false-positive allowlist + custom severity policy.

Loaded from ``~/.wpsecscan/policy.yml`` (or ``policy.json``). Format:

    severity_overrides:
      # When the named check fires THIS finding, force the severity to
      # the given value. Use to upgrade or downgrade.
      headers:
        Missing Content-Security-Policy: critical
      tls_modern:
        TLS 1.3 0-RTT (Early Data) enabled on .*: info  # regex against finding.title

    suppress:
      # Per-site finding suppressions. The key is the site URL; the value
      # is a list of {check_id, title_regex, reason}.
      https://example.com:
        - check_id: js_libraries
          title_regex: "jQuery 1\\."
          reason: "Vendor plugin we can't upgrade until 2026-12-01"
        - check_id: cors
          title_regex: ".*"
          reason: "Site intentionally exposes a public REST API"

The CLI scan path consults this policy after the scan completes and
either re-tags severities or drops findings entirely before any
reporter runs.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path


def _policy_path() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    yml = home / "policy.yml"
    if yml.exists():
        return yml
    return home / "policy.json"


def load() -> dict:
    """Load + return the policy. Returns {} when no file or invalid."""
    p = _policy_path()
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8")
        if p.suffix == ".yml":
            try:
                import yaml  # type: ignore[import-not-found]
                return yaml.safe_load(text) or {}
            except ImportError:
                # Hand-roll a tiny YAML-lite parser? Better: tell the user.
                return {"_error": "pyyaml not installed; policy.yml ignored. "
                          "Convert to policy.json or `pip install pyyaml`."}
        return json.loads(text) or {}
    except (OSError, ValueError):
        return {}


def apply_severity_overrides(report, policy: dict) -> int:
    """Walk findings and rewrite severity per `severity_overrides`. Returns
    the count of mutations."""
    overrides = (policy or {}).get("severity_overrides") or {}
    if not overrides:
        return 0
    n = 0
    for r in report.results:
        rules = overrides.get(r.check_id) or {}
        if not rules:
            continue
        compiled = [(re.compile(pattern, re.IGNORECASE), new_sev)
                     for pattern, new_sev in rules.items()]
        for f in r.findings:
            for rx, new_sev in compiled:
                if rx.search(f.title) and new_sev != f.severity:
                    f.severity = new_sev
                    n += 1
                    break
    return n


def _rule_matches(rule_if: dict, check_id: str, finding, target: str) -> bool:
    """Item #57 — evaluate a single severity_rules.if{} block. Every key in the
    block must match (AND). Supported keys:
      check, check_id            — exact match against check_id
      title_contains             — substring (case-insensitive) match in title
      title_regex                — regex match in title
      target_startswith          — target URL startswith match
      target_contains            — substring in target
      severity_eq                — current finding severity equals
    """
    cid_match = rule_if.get("check") or rule_if.get("check_id")
    if cid_match and cid_match != check_id:
        return False
    tc = rule_if.get("title_contains")
    if tc and tc.lower() not in (finding.title or "").lower():
        return False
    tr = rule_if.get("title_regex")
    if tr:
        try:
            if not re.search(tr, finding.title or "", re.IGNORECASE):
                return False
        except re.error:
            return False
    ts = rule_if.get("target_startswith")
    if ts and not (target or "").startswith(ts):
        return False
    tcn = rule_if.get("target_contains")
    if tcn and tcn not in (target or ""):
        return False
    se = rule_if.get("severity_eq")
    if se and se != finding.severity:
        return False
    return True


def apply_severity_rules(report, policy: dict) -> int:
    """Item #57 — boolean rule engine. Rules schema:

        severity_rules:
          - if:
              check: headers
              title_contains: "Content-Security-Policy"
              target_startswith: "https://prod"
            then:
              severity: critical
          - if:
              check_id: js_libraries
              title_regex: "jQuery 1\\."
            then:
              severity: low

    Rules are evaluated in declaration order; the first match wins per finding.
    Returns the count of mutations.
    """
    rules = (policy or {}).get("severity_rules") or []
    if not rules:
        return 0
    n = 0
    for r in report.results:
        for f in r.findings:
            for rule in rules:
                cond = (rule or {}).get("if") or {}
                action = (rule or {}).get("then") or {}
                new_sev = action.get("severity")
                if not new_sev:
                    continue
                if _rule_matches(cond, r.check_id, f, report.target):
                    if new_sev != f.severity:
                        f.severity = new_sev
                        n += 1
                    break  # first match wins
    return n


def apply_suppressions(report, policy: dict) -> int:
    """Drop findings that match any rule under `suppress[<target>]`.
    Returns the count of suppressed findings."""
    suppress = (policy or {}).get("suppress") or {}
    rules = suppress.get(report.target) or []
    if not rules:
        return 0
    compiled = []
    for rule in rules:
        cid = (rule or {}).get("check_id") or ""
        rx = (rule or {}).get("title_regex") or ".*"
        try:
            compiled.append((cid, re.compile(rx, re.IGNORECASE),
                              (rule or {}).get("reason", "")))
        except re.error:
            continue
    if not compiled:
        return 0
    n = 0
    for r in report.results:
        keep = []
        for f in r.findings:
            suppressed = False
            for cid, rx, _reason in compiled:
                if cid and cid != r.check_id:
                    continue
                if rx.search(f.title):
                    suppressed = True
                    n += 1
                    break
            if not suppressed:
                keep.append(f)
        r.findings = keep
    return n
