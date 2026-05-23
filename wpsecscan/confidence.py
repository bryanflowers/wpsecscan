"""Exploit-confidence indicator.

Separate from severity. A 'high' severity finding can still be 'low confidence
exploitable' (e.g. CVE matched but the endpoint behind a WAF), and a 'medium'
severity can be 'high confidence' (an actively-confirmed signature).

We use simple heuristics, not a model:
  - Finding title starts with "[CONFIRMED]" (our signature engine prefix) -> high
  - Aggressive payload finding (sqli/xss/ssrf/etc) with prove-extracted evidence -> high
  - WAF detected on this site (ctx['shared']['waf'] populated) -> lower the result by one tier
  - Plain CVE-match (version comparison only, no active probe) -> medium
  - Info-severity passive discovery findings -> low
"""
from __future__ import annotations

LEVELS = ("low", "medium", "high")
COLOR = {"low": "#8b949e", "medium": "#f0c674", "high": "#79e0d0"}


def compute_confidence(finding, check_id: str, waf_detected: bool = False) -> str:
    """Return 'low' / 'medium' / 'high' for a Finding."""
    title = (finding.title or "")
    sev = finding.severity or ""
    extra = getattr(finding, "extra", {}) or {}

    base = "medium"
    # [CONFIRMED] prefix means the signature engine verified the endpoint responded as vulnerable.
    if title.startswith("[CONFIRMED]"):
        base = "high"
    # The "prove" mechanism stashes proof artifacts in extra; if present, confidence is high.
    elif extra.get("proof") or extra.get("proof_audit"):
        base = "high"
    elif sev == "critical":
        base = "high"
    elif sev == "high":
        base = "medium"
    elif sev in ("low", "info"):
        base = "low"

    # A WAF in front of the site reduces actual exploitability — drop a tier.
    if waf_detected and base != "low":
        idx = LEVELS.index(base)
        base = LEVELS[max(0, idx - 1)]

    return base


def chip(level: str) -> str:
    """Short label for the badge."""
    return {
        "high":   "HIGH-CONFIDENCE",
        "medium": "MED-CONFIDENCE",
        "low":    "LOW-CONFIDENCE",
    }.get(level, level)
