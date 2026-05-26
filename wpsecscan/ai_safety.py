"""Round-59 #68-72 — AI / LLM output-safety wrappers.

These are NOT scanner checks. They wrap the `ai_assist` calls with
safety, observability, and cost-control. Every public function here
short-circuits when `WPSECSCAN_NO_AI=1` is set.

#68 Hallucination verification — re-prompt LLM with "is X true about
    target Y? answer yes/no with a citation". Pass-through verdict.
#69 Cost tracking — record token-equivalent + accumulated $-cost in
    `~/.wpsecscan/ai_cost.json` per backend.
#70 llama.cpp local backend — alternative to Ollama for users who want
    GGUF models running natively.
#71 Prompt-injection guard — strip control sequences from finding
    evidence before passing to LLM.
#72 Private-data masking — masks emails, IPs, API keys, credit cards
    before sending to a cloud LLM.

All public surface is at the bottom of the file.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path


# ---- #69 cost tracking ----

_COST_PER_1K = {
    "openai":    {"in": 0.0005, "out": 0.0015},   # gpt-4o-mini
    "anthropic": {"in": 0.001,  "out": 0.005},    # haiku
    "ollama":    {"in": 0.0,    "out": 0.0},      # local
    "llama_cpp": {"in": 0.0,    "out": 0.0},      # local
}


def _cost_path() -> Path:
    home = os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan")
    return Path(home) / "ai_cost.json"


def record_cost(backend: str, in_tokens: int, out_tokens: int) -> None:
    """Append usage; cap at the next sane million tokens to avoid runaway."""
    if os.environ.get("WPSECSCAN_NO_AI"):
        return
    backend = (backend or "").lower()
    rate = _COST_PER_1K.get(backend, {"in": 0, "out": 0})
    delta_usd = (in_tokens / 1000.0) * rate["in"] + (out_tokens / 1000.0) * rate["out"]
    path = _cost_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError):
        data = {}
    entry = data.setdefault(backend, {"in_tokens": 0, "out_tokens": 0, "usd": 0.0, "calls": 0})
    entry["in_tokens"] = int(entry.get("in_tokens", 0)) + max(0, int(in_tokens))
    entry["out_tokens"] = int(entry.get("out_tokens", 0)) + max(0, int(out_tokens))
    entry["usd"] = round(float(entry.get("usd", 0.0)) + delta_usd, 6)
    entry["calls"] = int(entry.get("calls", 0)) + 1
    entry["last"] = int(time.time())
    try:
        # symlink guard
        if path.is_symlink():
            path.unlink()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def cost_summary() -> dict:
    if os.environ.get("WPSECSCAN_NO_AI"):
        return {}
    path = _cost_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


# ---- #71 prompt-injection guard ----

# Strip control-bytes, sentinel-style markers, and obvious instruction
# subverters that adversaries might plant in finding evidence.
_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore (all )?(previous|above)\s+(instructions|prompts)"),
    re.compile(r"(?i)system\s*[:>]+"),
    re.compile(r"(?i)\\[/-]?(instruction|prompt|tool)\\[/-]?"),
    re.compile(r"<\|.*?\|>"),
    re.compile(r"\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x0b|\x0c|\x0e|\x1b"),
)


def strip_prompt_injection(text: str) -> str:
    """Best-effort: strip known prompt-injection markers from text before
    passing into the LLM."""
    if not text:
        return ""
    out = text
    for r in _PROMPT_INJECTION_PATTERNS:
        out = r.sub("[REDACTED]", out)
    return out


# ---- #72 private-data masking ----

_MASK_PATTERNS = (
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                            "[IP]"),
    (re.compile(r"\b(?:\d[ \-]?){13,19}\b"),                                 "[CARD]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                    "[AWS_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),                               "[GOOGLE_KEY]"),
    (re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),            "[STRIPE_KEY]"),
    (re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"),                                 "[GITHUB_PAT]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                                   "[SSN]"),
    # #61 — JWTs (three base64 segments separated by .) + WordPress session
    # cookies + bearer tokens. These appear in evidence blobs whenever an
    # auth probe captures a logged-in response.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "[JWT]"),
    (re.compile(r"\bwordpress_logged_in_[a-f0-9]{16,}\s*=\s*[^;\s]+",
                  re.IGNORECASE), "wordpress_logged_in_***=[SESSION_COOKIE]"),
    (re.compile(r"\bwordpress_sec_[a-f0-9]{16,}\s*=\s*[^;\s]+",
                  re.IGNORECASE), "wordpress_sec_***=[SESSION_COOKIE]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{20,}", re.IGNORECASE), "Bearer [TOKEN]"),
    (re.compile(r"\bX-WPSecScan-Token:\s*\S+", re.IGNORECASE), "X-WPSecScan-Token: [REDACTED]"),
)


def mask_private(text: str) -> str:
    if not text:
        return ""
    out = text
    for r, repl in _MASK_PATTERNS:
        out = r.sub(repl, out)
    return out


def safe_for_llm(text: str) -> str:
    """One-stop sanitiser: strip prompt injection AND mask PII before
    sending user-controlled scan output to a remote LLM. Pure function."""
    return mask_private(strip_prompt_injection(text or ""))


def redact_report_in_place(report) -> int:
    """#61: walk every finding in a ScanReport and replace JWTs / session
    cookies / bearer tokens / PII in evidence + remediation with mask
    placeholders. Mutates the report. Returns the count of redactions."""
    n = 0
    for r in getattr(report, "results", []) or []:
        for f in r.findings:
            if f.evidence:
                new_ev = mask_private(f.evidence)
                if new_ev != f.evidence:
                    n += 1
                    f.evidence = new_ev
            if f.remediation:
                new_rem = mask_private(f.remediation)
                if new_rem != f.remediation:
                    n += 1
                    f.remediation = new_rem
    return n


# ---- #68 hallucination verification ----

def verify_claim(claim: str, target_url: str) -> str:
    """Re-prompt the configured LLM with a yes/no verification of `claim`
    about `target_url`. Returns 'true' / 'false' / 'unknown'."""
    if os.environ.get("WPSECSCAN_NO_AI"):
        return "unknown"
    from .ai_assist import llm, is_configured
    if not is_configured():
        return "unknown"
    safe = safe_for_llm(claim)
    sys = ("You are a fact-checker. Answer with a single word: TRUE if the "
           "claim is likely correct based on common WordPress knowledge, "
           "FALSE if obviously wrong, UNKNOWN if you can't tell. Nothing else.")
    raw = (llm(f"Claim about {target_url}:\n\n{safe}", system=sys, max_tokens=10) or "").strip().lower()
    if raw.startswith("true"):
        return "true"
    if raw.startswith("false"):
        return "false"
    return "unknown"


# ---- #70 llama.cpp local backend ----

def _has_llama_cpp() -> bool:
    return bool(os.environ.get("WPSECSCAN_LLAMA_CPP_URL"))


def call_llama_cpp(prompt: str, *, system: str = "", max_tokens: int = 600,
                    timeout: float = 30.0) -> str:
    """Call a llama.cpp server (`server` binary's HTTP interface).

    Set `WPSECSCAN_LLAMA_CPP_URL=http://localhost:8080` (no trailing slash).
    Returns "" on any error.
    """
    if os.environ.get("WPSECSCAN_NO_AI"):
        return ""
    url = (os.environ.get("WPSECSCAN_LLAMA_CPP_URL") or "").rstrip("/")
    if not url:
        return ""
    import urllib.request
    from urllib.error import HTTPError, URLError
    body = json.dumps({
        "prompt": f"{system}\n\n{prompt}" if system else prompt,
        "n_predict": max_tokens,
        "temperature": 0.2,
        "stop": ["</s>"],
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/completion", data=body, method="POST",
        headers={"Content-Type": "application/json",
                  "User-Agent": "WPSecScan/ai_safety/llama_cpp"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return ""
            data = json.loads(r.read().decode("utf-8"))
        content = (data.get("content") or "").strip()
        # Best-effort cost tracking (0$/local but token-count for transparency)
        tokens = data.get("tokens_predicted") or len(content) // 4
        record_cost("llama_cpp", in_tokens=len(prompt) // 4, out_tokens=tokens)
        return content
    except (HTTPError, URLError, OSError, ValueError):
        return ""
