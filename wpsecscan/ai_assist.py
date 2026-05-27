"""#65-72 AI / LLM-assisted features (Bring-Your-Own-Key).

Supports three backends, all opt-in via env vars:
  - OpenAI: WPSECSCAN_OPENAI_API_KEY  (uses /v1/chat/completions, gpt-4o-mini default)
  - Anthropic: WPSECSCAN_ANTHROPIC_API_KEY  (uses /v1/messages, claude-haiku-4-5 default)
  - Ollama: WPSECSCAN_OLLAMA_URL (local http://localhost:11434 — no key needed)

Each function returns "" (empty string) if no backend is configured. Never
ships a key, never raises if a backend is unreachable.

Implements:
  #65 LLM-generated remediation augmentation
  #66 LLM executive summary
  #67 AI-mutated payload variants
  #68 Natural-language query against report
  #69 Multi-step exploit-chain explanation
  #70 Conversational scan REPL (--chat)
  #71 Fix PR description generator
  #72 Replacement-plugin recommender
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.error import HTTPError, URLError


def _has_openai_key() -> bool:
    return bool(os.environ.get("WPSECSCAN_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY"))


def _has_anthropic_key() -> bool:
    return bool(os.environ.get("WPSECSCAN_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))


def _has_ollama() -> bool:
    return bool(os.environ.get("WPSECSCAN_OLLAMA_URL"))


def is_configured() -> bool:
    return _has_openai_key() or _has_anthropic_key() or _has_ollama()


def _call_openai(prompt: str, *, system: str = "", model: str = "gpt-4o-mini",
                  max_tokens: int = 600, timeout: float = 20.0) -> str:
    key = os.environ.get("WPSECSCAN_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return ""
    body = json.dumps({
        "model": model,
        "messages": ([{"role": "system", "content": system}] if system else []) + [
            {"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body, method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "User-Agent": "WPSecScan/ai_assist"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return ""
            data = json.loads(r.read().decode("utf-8"))
        return (data.get("choices", [{}])[0].get("message", {}).get("content", "") or "").strip()
    except (HTTPError, URLError, OSError, ValueError):
        return ""


def _call_anthropic(prompt: str, *, system: str = "", model: str = "claude-haiku-4-5",
                     max_tokens: int = 600, timeout: float = 20.0) -> str:
    key = os.environ.get("WPSECSCAN_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return ""
    body = json.dumps({
        "model": model,
        "system": system or "You are a defensive WordPress security expert. Be concise.",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body, method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json", "User-Agent": "WPSecScan/ai_assist"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return ""
            data = json.loads(r.read().decode("utf-8"))
        blocks = data.get("content", [])
        return ("".join(b.get("text", "") for b in blocks if isinstance(b, dict))).strip()
    except (HTTPError, URLError, OSError, ValueError):
        return ""


def _call_ollama(prompt: str, *, system: str = "", model: str = "llama3",
                  timeout: float = 30.0) -> str:
    url = os.environ.get("WPSECSCAN_OLLAMA_URL", "").rstrip("/")
    if not url:
        return ""
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "system": system,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/api/generate", data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "WPSecScan/ai_assist"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return ""
            data = json.loads(r.read().decode("utf-8"))
        return (data.get("response", "") or "").strip()
    except (HTTPError, URLError, OSError, ValueError):
        return ""


def llm(prompt: str, *, system: str = "", max_tokens: int = 600) -> str:
    """Dispatch to whichever backend is configured. Returns "" if none."""
    if _has_anthropic_key():
        return _call_anthropic(prompt, system=system, max_tokens=max_tokens)
    if _has_openai_key():
        return _call_openai(prompt, system=system, max_tokens=max_tokens)
    if _has_ollama():
        return _call_ollama(prompt, system=system)
    return ""


# ---- High-level helpers, one per feature ----

def remediation_augment(finding) -> str:
    """#65 — return AI-suggested concrete commands / config snippets on top of
    the static remediation text. Returns "" if no LLM."""
    import os as _os
    if _os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    sys_msg = ("You are a defensive WordPress security expert. Given a finding "
                "with a generic remediation, return 3 CONCRETE config snippets or "
                "shell commands that fix it. No prose, just the snippets. Max 200 words.")
    return llm(f"Title: {finding.title}\nSeverity: {finding.severity}\nExisting remediation: {finding.remediation}",
                system=sys_msg, max_tokens=400)


def executive_summary(report) -> str:
    """#66 — natural-language abstract for the C-suite.

    DATA WARNING: This function sends the target URL, risk score, and the
    top-3 critical finding TITLES (not evidence or remediation) to whichever
    LLM provider is configured. Set `WPSECSCAN_NO_AI=1` to hard-disable
    every AI feature regardless of API-key presence. For GDPR-sensitive
    use cases prefer a local Ollama backend over the cloud providers.
    """
    import os
    if os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    s = report.summary
    sys_msg = ("Summarise a WordPress security scan in 3 short paragraphs for a "
                "non-technical CEO. Plain English. No jargon. Focus on business risk.")
    return llm(
        f"Target: {report.target}\nRisk score: {report.risk_score}/100\n"
        f"Findings: {s.get('critical',0)} critical, {s.get('high',0)} high, "
        f"{s.get('medium',0)} medium, {s.get('low',0)} low.\nTop 3 critical titles:\n"
        + "\n".join(f"  - {f.title}" for r in report.results
                     for f in r.findings if f.severity == "critical")[:5],
        system=sys_msg, max_tokens=500)


def query(report, question: str) -> str:
    """#68 — natural-language query. Returns LLM-generated answer."""
    import os as _os
    if _os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    findings_text = "\n".join(
        f"[{f.severity}] {r.check_id}: {f.title}"
        for r in report.results for f in r.findings)[:8000]
    sys_msg = "Answer the user's question about this scan report. Be brief, direct."
    return llm(f"Question: {question}\n\nReport findings:\n{findings_text}",
                system=sys_msg, max_tokens=400)


def replacement_plugin_recommender(vulnerable_plugin: str) -> str:
    """#72 — suggest 3 maintained alternatives to a vulnerable plugin."""
    import os as _os
    if _os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    sys_msg = ("You're a WordPress consultant. Given a vulnerable plugin name, "
                "suggest 3 actively-maintained alternatives with comparable features. "
                "Format: bullet list, name + 1-line description + wp.org URL.")
    return llm(f"Vulnerable plugin: {vulnerable_plugin}", system=sys_msg, max_tokens=300)


def fix_pr_body(finding) -> str:
    """#71 — auto-write a GitHub PR description that fixes this finding."""
    import os as _os
    if _os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    sys_msg = ("Write a GitHub pull-request body that fixes this WordPress security "
                "finding. Sections: Summary, Root cause, Fix (with diff snippets), "
                "Test plan. Markdown. Max 250 words.")
    return llm(f"Title: {finding.title}\nEvidence: {finding.evidence}\n"
                f"Existing remediation: {finding.remediation}",
                system=sys_msg, max_tokens=500)


def fix_pr_diff(finding) -> str:
    """G89 (v2.6.0) — draft a unified-diff patch alongside the PR body.

    Returns a single string containing one or more `diff --git ...` chunks
    with `---` / `+++` / `@@` headers and `+`/`-` line markers, ready to
    be saved as a `.patch` file and applied with `git apply`.

    Returns empty string if no AI backend is configured.
    """
    import os as _os
    if _os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    sys_msg = (
        "Output ONLY a unified diff (no prose) that fixes this WordPress "
        "security finding. Use 'diff --git a/<file> b/<file>' headers, "
        "'@@ line ranges @@' hunks, and +/- markers. Pick the canonical "
        "WordPress file paths (wp-config.php, .htaccess, theme functions.php, "
        "or the named plugin file). If the fix isn't a code change but a "
        "wp-admin Setting toggle, output:\n"
        "  # CONFIG-ONLY: <one-line description>\n"
        "instead of a diff. No commentary."
    )
    return llm(
        f"Title: {finding.title}\nEvidence: {finding.evidence}\n"
        f"Remediation: {finding.remediation}\nURL: {finding.url}",
        system=sys_msg, max_tokens=800,
    )


_CLIENT_SUMMARY_AUDIENCES = {
    "client": (
        "You are explaining a WordPress security finding to a non-technical client "
        "(the site owner — a restaurant, charity, e-commerce shop). Write ONE plain-"
        "English sentence describing the risk in their terms — no acronyms, no "
        "jargon, no code. Then a second sentence on why it matters to their "
        "business (lost trust, downtime, blocked checkout, data fine). 35 words max."
    ),
    "dev": (
        "You are explaining a WordPress security finding to a mid-level developer. "
        "Two sentences. Sentence 1: the technical defect. Sentence 2: the fix, "
        "named precisely (file/header/setting). Keep terse — no marketing language."
    ),
    "exec": (
        "You are explaining a WordPress security finding to a non-technical "
        "executive. ONE sentence on business risk in dollars / regulatory / "
        "reputational terms. ONE sentence on the time-to-fix. 30 words max."
    ),
}


def client_summarize_finding(finding, *, audience: str = "client") -> str:
    """FEAT-010 — rewrite a single finding into plain-English text for the
    given audience. Returns "" if no LLM backend or AI disabled.

    Caller is expected to attach the result to ``finding.extra['client_summary']``.
    Only call this on the high-signal findings (critical/high) — running it on
    every info-level entry burns tokens without value.
    """
    import os as _os
    if _os.environ.get("WPSECSCAN_NO_AI") or not is_configured():
        return ""
    sys_msg = _CLIENT_SUMMARY_AUDIENCES.get(audience) or _CLIENT_SUMMARY_AUDIENCES["client"]
    prompt = (
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity}\n"
        f"Evidence: {(finding.evidence or '')[:300]}\n"
        f"Remediation: {(finding.remediation or '')[:300]}\n"
    )
    return llm(prompt, system=sys_msg, max_tokens=120)


def client_summarize_report(report, *, audience: str = "client",
                              min_severity: str = "high",
                              max_findings: int = 25) -> int:
    """FEAT-010 — attach ``extra['client_summary']`` to every finding at or
    above ``min_severity`` (default "high"). Caps total LLM calls at
    ``max_findings`` to bound cost. Returns count of summaries actually
    generated."""
    if audience not in _CLIENT_SUMMARY_AUDIENCES:
        return 0
    from .models import SEVERITY_RANK
    floor = SEVERITY_RANK.get(min_severity, SEVERITY_RANK["high"])
    candidates = [
        f for r in report.results for f in r.findings
        if SEVERITY_RANK.get(f.severity, 0) >= floor
    ]
    candidates.sort(key=lambda f: -SEVERITY_RANK.get(f.severity, 0))
    written = 0
    for f in candidates[:max_findings]:
        text = client_summarize_finding(f, audience=audience)
        if text:
            f.extra["client_summary"] = text
            f.extra["client_summary_audience"] = audience
            written += 1
    return written


def chain_explanation(findings: list) -> str:
    """#69 — narrate how to chain multiple findings into one exploit."""
    if not is_configured() or not findings:
        return ""
    titles = "\n".join(f"  - [{f.severity}] {f.title}" for f in findings[:5])
    return llm(
        f"Findings:\n{titles}\n\nExplain how an attacker could chain "
        f"these into a single compromise. Max 300 words.",
        system="You are a defensive security expert explaining attacker chains.",
        max_tokens=500,
    )
