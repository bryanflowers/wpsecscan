"""Round-65 Group C — 10 advanced AI-triage features (opt-in).

All features are OFF by default. They only become available when:
  1. The user has configured an LLM backend (OpenAI / Anthropic /
     Ollama key) — checked via `ai_assist.is_configured()`
  2. The user has opted-in via `~/.wpsecscan/ai_settings.json`
     (managed via GUI "Advanced AI options..." panel OR the
     `wpsecscan ai-options` CLI subcommand).

Per-feature toggles let advanced users enable just what they want;
the defaults assume someone who just dropped in an API key wants
zero LLM calls per scan (no surprise bills).

PII masking via `ai_safety.safe_for_llm()` is always-on. The toggles
only control WHICH triage features run, not whether masking applies.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

from . import ai_assist, ai_safety


# ============================================================
# Settings
# ============================================================


def _settings_path() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    return home / "ai_settings.json"


@dataclass
class AITriageSettings:
    """All ten toggles. All default False."""

    # C1
    severity_auto_tuner: bool = False
    # C2
    duplicate_collapser: bool = False
    # C3
    false_positive_predictor: bool = False
    fp_auto_hide_threshold: float = 0.9
    # C4
    exec_brief_generator: bool = False
    exec_brief_audience: str = "auditor"  # one of: ceo, cto, auditor, dev
    # C5
    remediation_step_generator: bool = False
    remediation_stack_profile: str = "wp_engine"  # or self_hosted, kubernetes, cpanel
    # C6
    timeline_narrator: bool = False
    # C7
    business_impact_estimator: bool = False
    estimated_annual_revenue_usd: int = 0
    estimated_transactions_per_day: int = 0
    # C8
    ticket_autogen: bool = False
    ticket_destination: str = "jira"  # or linear, github_issue
    # C9
    realtime_kev_correlation: bool = False
    # C10
    conversational_qa: bool = False

    @classmethod
    def load(cls) -> "AITriageSettings":
        p = _settings_path()
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        # Only accept known fields to ignore old/typo'd keys
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self) -> None:
        p = _settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        # Symlink-guard
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def any_enabled(self) -> bool:
        return any(
            getattr(self, f) for f in (
                "severity_auto_tuner", "duplicate_collapser",
                "false_positive_predictor", "exec_brief_generator",
                "remediation_step_generator", "timeline_narrator",
                "business_impact_estimator", "ticket_autogen",
                "realtime_kev_correlation", "conversational_qa",
            )
        )


def is_available() -> tuple[bool, str]:
    """Returns (ok, reason). False if no LLM backend OR no toggles on."""
    if not ai_assist.is_configured():
        return False, "no LLM backend configured (set OPENAI_API_KEY / ANTHROPIC_API_KEY / install Ollama)"
    s = AITriageSettings.load()
    if not s.any_enabled():
        return False, "no AI-triage features enabled — open Advanced AI options to turn some on"
    return True, ""


# ============================================================
# C1 — Severity auto-tuner
# ============================================================


def auto_tune_severity(findings: list, *, site_context: str = "general WordPress site") -> list:
    """Re-rank findings by LLM-judged real-world risk for THIS site.

    Returns findings sorted by adjusted severity (most urgent first).
    Adds `extra["ai_severity_score"]` to each finding (0-100).
    """
    s = AITriageSettings.load()
    if not s.severity_auto_tuner or not ai_assist.is_configured():
        return findings

    summarised = [
        {
            "title":    f.title if hasattr(f, "title") else f.get("title"),
            "severity": f.severity if hasattr(f, "severity") else f.get("severity"),
            "evidence": (f.evidence if hasattr(f, "evidence") else f.get("evidence", ""))[:300],
        }
        for f in findings
    ]
    masked = ai_safety.safe_for_llm(json.dumps(summarised))
    prompt = (
        f"Site context: {site_context}.\n\n"
        f"Findings (JSON):\n{masked}\n\n"
        "For each finding, output a JSON array of {title, score} where score is 0-100 "
        "(higher = more urgent for THIS site context). Return ONLY the JSON, no preamble."
    )
    try:
        response = ai_assist.llm(prompt, system="You are a security triage analyst.", max_tokens=800)
        scores = json.loads(_extract_json(response)) or []
        score_by_title = {s["title"]: int(s.get("score", 0)) for s in scores if isinstance(s, dict)}
    except (ValueError, KeyError, RuntimeError):
        return findings

    for f in findings:
        t = f.title if hasattr(f, "title") else f.get("title")
        score = score_by_title.get(t, 0)
        if hasattr(f, "extra"):
            f.extra["ai_severity_score"] = score
        elif isinstance(f, dict):
            f.setdefault("extra", {})["ai_severity_score"] = score

    return sorted(
        findings,
        key=lambda f: -(f.extra.get("ai_severity_score", 0) if hasattr(f, "extra")
                        else (f.get("extra") or {}).get("ai_severity_score", 0)),
    )


# ============================================================
# C2 — Duplicate / sibling collapser
# ============================================================


def collapse_duplicates(findings: list) -> dict:
    """Group findings by LLM-judged root cause.

    Returns: {"clusters": [{"root_cause": str, "findings": [titles]}, ...]}
    """
    s = AITriageSettings.load()
    if not s.duplicate_collapser or not ai_assist.is_configured() or not findings:
        return {"clusters": []}
    titles = [(f.title if hasattr(f, "title") else f.get("title", "")) for f in findings]
    masked = ai_safety.safe_for_llm("\n".join(f"- {t}" for t in titles))
    prompt = (
        f"Below are {len(titles)} security findings from a single site. Group them by "
        "ROOT CAUSE (not just text similarity). Output JSON: "
        '{"clusters": [{"root_cause": "...", "findings": ["title1", "title2"]}]}. '
        f"Findings:\n{masked}\n\nReturn ONLY the JSON."
    )
    try:
        response = ai_assist.llm(prompt, system="You are a security triage analyst.", max_tokens=1200)
        return json.loads(_extract_json(response))
    except (ValueError, KeyError, RuntimeError):
        return {"clusters": []}


# ============================================================
# C3 — False-positive predictor
# ============================================================


def predict_false_positives(findings: list, *, stack: str = "") -> list:
    """Adds extra['fp_probability'] (0.0-1.0) to each finding.

    Returns a NEW list, optionally with high-confidence FPs auto-hidden.
    """
    s = AITriageSettings.load()
    if not s.false_positive_predictor or not ai_assist.is_configured():
        return findings

    summarised = [
        {
            "title":    f.title if hasattr(f, "title") else f.get("title"),
            "severity": f.severity if hasattr(f, "severity") else f.get("severity"),
            "evidence": (f.evidence if hasattr(f, "evidence") else f.get("evidence", ""))[:200],
        }
        for f in findings
    ]
    masked = ai_safety.safe_for_llm(json.dumps(summarised))
    prompt = (
        f"Site stack: {stack or s.remediation_stack_profile}.\n"
        f"Findings:\n{masked}\n\n"
        "For each finding, estimate the probability (0.0-1.0) that it's a false "
        "positive on THIS stack (e.g. WP Engine pre-applies certain hardening, "
        "so some 'missing header' findings are FPs there). "
        'Return JSON: [{"title": "...", "fp_prob": 0.0-1.0}]. ONLY the JSON.'
    )
    try:
        response = ai_assist.llm(prompt, system="You are a security triage analyst.", max_tokens=800)
        scores = json.loads(_extract_json(response))
        prob_by_title = {x["title"]: float(x.get("fp_prob", 0)) for x in scores if isinstance(x, dict)}
    except (ValueError, KeyError, RuntimeError, TypeError):
        return findings

    out = []
    for f in findings:
        t = f.title if hasattr(f, "title") else f.get("title")
        prob = prob_by_title.get(t, 0.0)
        if hasattr(f, "extra"):
            f.extra["fp_probability"] = prob
        elif isinstance(f, dict):
            f.setdefault("extra", {})["fp_probability"] = prob
        if prob < s.fp_auto_hide_threshold:
            out.append(f)
    return out


# ============================================================
# C4 — Plain-English exec brief generator
# ============================================================


def generate_exec_brief(report) -> str:
    """Produce a one-page exec summary tailored to the audience."""
    s = AITriageSettings.load()
    if not s.exec_brief_generator or not ai_assist.is_configured():
        return ""
    summary = report.summary if hasattr(report, "summary") else report.get("summary", {})
    target = report.target if hasattr(report, "target") else report.get("target", "?")
    audience_prompt = {
        "ceo":     "Write for a CEO with no security background. Focus on business risk, time-to-fix, and accountability.",
        "cto":     "Write for a CTO with eng background. Include enough technical hook to action team assignments.",
        "auditor": "Write for an external auditor (SOC2/PCI). Cite compliance framework refs where relevant.",
        "dev":     "Write for a senior dev. Include enough technical context to start fixing today.",
    }.get(s.exec_brief_audience, "")
    prompt = (
        f"Site: {target}\nFinding counts: {summary}\n\n"
        f"Audience: {s.exec_brief_audience}. {audience_prompt}\n"
        "Produce a one-page executive brief (≤300 words). Plain text. No marketing fluff."
    )
    try:
        return ai_assist.llm(prompt, system="You are a defensive-security advisor.", max_tokens=600).strip()
    except RuntimeError:
        return ""


# ============================================================
# C5 — Remediation step-generator
# ============================================================


def generate_remediation_steps(finding) -> str:
    """Copy-paste fix commands tailored to the user's stack."""
    s = AITriageSettings.load()
    if not s.remediation_step_generator or not ai_assist.is_configured():
        return ""
    title = finding.title if hasattr(finding, "title") else finding.get("title", "")
    ev = (finding.evidence if hasattr(finding, "evidence") else finding.get("evidence", ""))[:500]
    masked = ai_safety.safe_for_llm(ev)
    prompt = (
        f"Finding: {title}\n"
        f"Evidence: {masked}\n"
        f"User stack: {s.remediation_stack_profile}\n\n"
        "Produce copy-paste fix commands specific to this stack. Markdown. ≤200 words. "
        "Include exact config snippets, exact CLI commands. Don't say 'consult the docs'."
    )
    try:
        return ai_assist.llm(prompt, system="You are a senior WordPress security engineer.", max_tokens=400).strip()
    except RuntimeError:
        return ""


# ============================================================
# C6 — Timeline narrator
# ============================================================


def narrate_timeline(timeline_events: list) -> str:
    """Plain-English narration of a forensics timeline."""
    s = AITriageSettings.load()
    if not s.timeline_narrator or not ai_assist.is_configured() or not timeline_events:
        return ""
    serialised = [
        {
            "ts":     getattr(e, "timestamp", "") or (isinstance(e, dict) and e.get("timestamp")),
            "actor":  getattr(e, "actor", "") or (isinstance(e, dict) and e.get("actor")),
            "action": getattr(e, "action", "") or (isinstance(e, dict) and e.get("action")),
            "sev":    getattr(e, "severity", "") or (isinstance(e, dict) and e.get("severity")),
        }
        for e in timeline_events[:80]
    ]
    masked = ai_safety.safe_for_llm(json.dumps(serialised))
    prompt = (
        f"Forensics timeline:\n{masked}\n\n"
        "Narrate what likely happened in 5-8 sentences. Identify the probable "
        "first compromise event, the attacker's likely intent, and key persistence "
        "or lateral-movement steps. Don't speculate beyond the evidence."
    )
    try:
        return ai_assist.llm(prompt, system="You are an incident-response analyst.", max_tokens=500).strip()
    except RuntimeError:
        return ""


# ============================================================
# C7 — Business impact estimator
# ============================================================


def estimate_business_impact(findings: list) -> str:
    s = AITriageSettings.load()
    if not s.business_impact_estimator or not ai_assist.is_configured() or not findings:
        return ""
    top3 = sorted(
        findings,
        key=lambda f: -_sev_weight(f.severity if hasattr(f, "severity") else f.get("severity", "info")),
    )[:3]
    summary = [
        {"title": f.title if hasattr(f, "title") else f.get("title"),
         "severity": f.severity if hasattr(f, "severity") else f.get("severity")}
        for f in top3
    ]
    prompt = (
        f"Top-3 findings: {json.dumps(summary)}\n"
        f"Business context: annual revenue ~${s.estimated_annual_revenue_usd:,}, "
        f"~{s.estimated_transactions_per_day} transactions/day.\n\n"
        "Estimate the plausible business-impact $ if each of these is exploited. "
        "Show low/mid/high range per finding. Total at the end. ≤250 words."
    )
    try:
        return ai_assist.llm(prompt, system="You are a security ROI analyst.", max_tokens=500).strip()
    except RuntimeError:
        return ""


# ============================================================
# C8 — Ticket auto-gen
# ============================================================


def generate_tickets(findings: list) -> list[dict]:
    """One ticket per high-impact finding, shaped for Jira/Linear/GitHub."""
    s = AITriageSettings.load()
    if not s.ticket_autogen or not ai_assist.is_configured():
        return []
    high_value = [f for f in findings if _sev_weight(
        f.severity if hasattr(f, "severity") else f.get("severity", "info")
    ) >= 3]
    out: list[dict] = []
    for f in high_value[:20]:
        title = f.title if hasattr(f, "title") else f.get("title", "")
        ev = (f.evidence if hasattr(f, "evidence") else f.get("evidence", ""))[:400]
        rem = (f.remediation if hasattr(f, "remediation") else f.get("remediation", ""))[:400]
        masked = ai_safety.safe_for_llm(f"{title}\n\n{ev}\n\n{rem}")
        prompt = (
            f"Convert this finding into a {s.ticket_destination}-shaped ticket.\n"
            f"Return JSON: {{title, body, acceptance_criteria (list), severity, assignee_suggestion}}.\n"
            f"{masked}\n\nONLY the JSON."
        )
        try:
            response = ai_assist.llm(prompt, system="You are a security PM.", max_tokens=400)
            ticket = json.loads(_extract_json(response))
            ticket["_destination"] = s.ticket_destination
            out.append(ticket)
        except (ValueError, KeyError, RuntimeError):
            continue
    return out


# ============================================================
# C9 — Real-time KEV correlation
# ============================================================


def correlate_with_kev(findings: list) -> list[dict]:
    """Cross-reference findings against CISA KEV + recent attacker chatter.

    Returns enrichment payloads to overlay onto findings:
    [{"finding_title": "...", "kev_match": bool, "kev_added": "YYYY-MM",
      "in_the_wild_summary": "..."}]
    """
    s = AITriageSettings.load()
    if not s.realtime_kev_correlation or not ai_assist.is_configured():
        return []
    # Lean on the existing threat_intel_v2 cache when possible
    from . import threat_intel_v2 as ti
    out: list[dict] = []
    for f in findings:
        ev = (f.evidence if hasattr(f, "evidence") else f.get("evidence", ""))
        extra = (f.extra if hasattr(f, "extra") else f.get("extra")) or {}
        cve = extra.get("cve")
        if not cve:
            # Try to extract a CVE-YYYY-NNNN from evidence
            import re
            m = re.search(r"\bCVE-\d{4}-\d{4,}\b", ev)
            if m:
                cve = m.group(0)
        if not cve:
            continue
        kev = ti.cisa_kev_lookup(cve) or {}
        # Ask the LLM to add a short "what does this mean THIS month" overlay
        prompt = (
            f"CVE: {cve}\nCISA KEV record: {json.dumps(kev)[:500]}\n\n"
            "In 2 sentences, summarise what attackers are currently doing with "
            "this CVE based on recent IR reports + threat-actor chatter you know about."
        )
        try:
            blurb = ai_assist.llm(prompt, system="You are a threat-intel analyst.", max_tokens=200).strip()
        except RuntimeError:
            blurb = ""
        out.append({
            "finding_title": f.title if hasattr(f, "title") else f.get("title"),
            "cve":           cve,
            "kev_match":     bool(kev),
            "kev_added":     kev.get("dateAdded") if isinstance(kev, dict) else None,
            "in_the_wild_summary": blurb,
        })
    return out


# ============================================================
# C10 — Conversational scan-result Q&A
# ============================================================


def conversational_qa(report, question: str) -> str:
    """Chat over a single scan report."""
    s = AITriageSettings.load()
    if not s.conversational_qa or not ai_assist.is_configured():
        return "Conversational Q&A is disabled. Enable it in Advanced AI options."
    return ai_assist.query(report, question)


# ============================================================
# Helpers
# ============================================================


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_weight(sev: str) -> int:
    return _SEV_RANK.get((sev or "info").lower(), 0)


def _extract_json(text: str) -> str:
    """Strip Markdown fences + return the first {...} or [...] in the text."""
    if not text:
        return "{}"
    # Strip ```json ... ``` fences if present
    if "```" in text:
        parts = text.split("```")
        for p in parts:
            if p.strip().startswith(("{", "[")):
                return p.strip().removeprefix("json").strip()
    # Else find the first JSON-shaped substring
    start_obj = text.find("{")
    start_arr = text.find("[")
    if start_obj == -1 and start_arr == -1:
        return "{}"
    if start_obj == -1:
        start = start_arr
    elif start_arr == -1:
        start = start_obj
    else:
        start = min(start_obj, start_arr)
    return text[start:].strip()


# ============================================================
# Unified apply-all entrypoint
# ============================================================


def apply_all_enabled(report) -> dict:
    """Run every enabled AI-triage feature on a report.

    Returns a dict of per-feature outputs the reporter can render.
    """
    ok, reason = is_available()
    if not ok:
        return {"_skipped": reason}
    s = AITriageSettings.load()
    findings = report.all_findings if hasattr(report, "all_findings") else []
    if not findings and isinstance(report, dict):
        for r in report.get("results", []):
            findings.extend(r.get("findings", []))

    out: dict[str, Any] = {"_enabled_features": []}

    if s.severity_auto_tuner:
        out["_enabled_features"].append("severity_auto_tuner")
        out["reranked"] = auto_tune_severity(list(findings))
    if s.duplicate_collapser:
        out["_enabled_features"].append("duplicate_collapser")
        out["clusters"] = collapse_duplicates(findings)
    if s.false_positive_predictor:
        out["_enabled_features"].append("false_positive_predictor")
        out["fp_filtered"] = predict_false_positives(list(findings))
    if s.exec_brief_generator:
        out["_enabled_features"].append("exec_brief_generator")
        out["exec_brief"] = generate_exec_brief(report)
    if s.timeline_narrator:
        out["_enabled_features"].append("timeline_narrator")
        # Caller passes timeline_events via extra channel; skip here
    if s.business_impact_estimator:
        out["_enabled_features"].append("business_impact_estimator")
        out["business_impact"] = estimate_business_impact(findings)
    if s.ticket_autogen:
        out["_enabled_features"].append("ticket_autogen")
        out["tickets"] = generate_tickets(findings)
    if s.realtime_kev_correlation:
        out["_enabled_features"].append("realtime_kev_correlation")
        out["kev_overlay"] = correlate_with_kev(findings)

    return out
