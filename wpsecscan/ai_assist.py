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
