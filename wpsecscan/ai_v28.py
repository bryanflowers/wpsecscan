"""v2.8.1 AI features (F35-F48 except F39 + F46 which are rolled to v2.9.0).

Each function is a minimal-viable implementation that:
  * Returns a real result when keys/deps are available
  * Returns a structured "skipped: <why>" dict otherwise
  * Never raises on missing optional deps (httpx/openai/etc.)

Keeps optional. None of these are wired into the scan pipeline by
default — they're called from CLI subcommands or programmatic
integrations.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


def _home() -> Path:
    from .history import _home as _h
    return _h()


# ---------------------------------------------------------------------------
# F35 — Agentic remediation loop
# ---------------------------------------------------------------------------
def agentic_remediation_loop(finding: dict, *, max_iters: int = 3,
                              llm_fn: Any = None) -> dict:
    """Iteratively ask an LLM for a remediation plan, refine on each pass.

    `llm_fn(prompt: str) -> str` is the only required dep. If not passed,
    falls back to ai_assist.assist if available, or returns skipped.
    """
    if llm_fn is None:
        try:
            from . import ai_assist as _aa
            llm_fn = getattr(_aa, "assist", None)
        except ImportError:
            llm_fn = None
    if not callable(llm_fn):
        return {"status": "skipped",
                 "reason": "no llm_fn available (set OPENAI_API_KEY + ai_assist)"}
    plan = ""
    for i in range(max_iters):
        prompt = (
            f"Iteration {i + 1}/{max_iters}.\n"
            f"Finding: {json.dumps(finding)[:1500]}\n"
            f"Previous plan: {plan or '(none)'}\n"
            "Produce a SPECIFIC remediation plan with shell commands. "
            "Identify and fix gaps in the previous plan. When you have a "
            "complete plan, end the response with the literal token "
            "[PLAN COMPLETE]."
        )
        try:
            plan = (llm_fn(prompt) or "").strip()
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "iter": i + 1, "error": str(e)}
        # v2.8.2 L7 — `"DONE"` matched in unrelated text ("DONE: update the
        # plugin"). Use a distinctive sentinel mentioned in the prompt.
        if "[PLAN COMPLETE]" in plan or len(plan) > 4000:
            break
    return {"status": "ok", "iterations": i + 1, "plan": plan}


# ---------------------------------------------------------------------------
# F36 — Self-improving scan plan
# ---------------------------------------------------------------------------
def self_improving_scan_plan(target: str, *,
                              history_n: int = 5) -> dict:
    """Look at the last N scans of `target`; if some checks always come up
    empty, suggest disabling them. If some checks always trigger, suggest
    promoting them to --aggressive."""
    try:
        from . import history as _h
    except ImportError:
        return {"status": "skipped", "reason": "history module missing"}
    snaps = []
    try:
        for ent in _h.list_snapshots(target)[:history_n]:
            p = _h.snapshot_path(target, ent.get("ts"))
            if p and p.exists():
                snaps.append(json.loads(p.read_text(encoding="utf-8")))
    except (AttributeError, OSError, ValueError):
        return {"status": "skipped", "reason": "no usable snapshot history"}
    if len(snaps) < 2:
        return {"status": "skipped", "reason": f"only {len(snaps)} snapshot(s); need 2+"}
    # Count per-check finding totals
    totals: dict[str, int] = {}
    for s in snaps:
        for r in (s.get("results") or []):
            totals[r.get("check_id", "?")] = totals.get(r.get("check_id", "?"), 0) + \
                len(r.get("findings") or [])
    quiet = [cid for cid, n in totals.items() if n == 0]
    loud = [cid for cid, n in totals.items() if n >= len(snaps) * 3]
    return {
        "status": "ok",
        "scans_analysed": len(snaps),
        "always_quiet": sorted(quiet)[:20],
        "always_loud": sorted(loud)[:20],
        "suggestion": (
            f"Consider --disable-check on {len(quiet)} always-quiet check(s); "
            f"keep {len(loud)} always-loud check(s) prioritised."),
    }


# ---------------------------------------------------------------------------
# F37 — Admin-panel screenshot vision analyser
# ---------------------------------------------------------------------------
def screenshot_vision_analyse(png_path: str, *, llm_fn: Any = None) -> dict:
    """Send an admin-panel screenshot to a multimodal LLM and ask for
    security observations. Requires a vision-capable model.

    llm_fn signature: `(prompt: str, image_path: str) -> str`.
    """
    if not Path(png_path).exists():
        return {"status": "error", "reason": f"{png_path} not found"}
    if not callable(llm_fn):
        return {"status": "skipped",
                 "reason": "no vision llm_fn supplied; pass a callable"}
    try:
        out = llm_fn(
            "Analyse this WP-admin screenshot for security issues: "
            "exposed UI, predictable URLs, leaked tokens, unsafe defaults.",
            png_path,
        ) or ""
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": str(e)}
    return {"status": "ok", "analysis": out.strip()}


# ---------------------------------------------------------------------------
# F38 — Visual diff between scans + AI annotation
# ---------------------------------------------------------------------------
def visual_diff_summarise(old_report: dict, new_report: dict, *,
                           llm_fn: Any = None) -> dict:
    """Compute a structural diff between two snapshot JSONs; if llm_fn is
    supplied, also produce a 3-sentence prose summary of what changed."""
    def _fp(report: dict) -> set[str]:
        out: set[str] = set()
        for r in (report.get("results") or []):
            cid = r.get("check_id", "?")
            for f in (r.get("findings") or []):
                out.add(f"{cid}::{f.get('severity')}::{(f.get('title') or '')[:60]}")
        return out
    old_set = _fp(old_report)
    new_set = _fp(new_report)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    summary = None
    if callable(llm_fn) and (added or removed):
        try:
            prompt = ("Two consecutive wpsecscan scans differ:\n"
                       f"Added findings: {added[:20]}\n"
                       f"Removed findings: {removed[:20]}\n"
                       "Summarise in 3 sentences for an exec audience.")
            summary = (llm_fn(prompt) or "").strip()
        except Exception:  # noqa: BLE001
            summary = None
    return {
        "status": "ok",
        "added_count": len(added),
        "removed_count": len(removed),
        "added": added[:50],
        "removed": removed[:50],
        "ai_summary": summary,
    }


# F40 — Voice query (REMOVED in v2.8.2 M3)
# v2.8.1 shipped a `voice_query` stub that always returned skipped: it
# checked WHISPER_CPP_BIN but had no audio-capture logic. Removed to
# avoid promising a feature that didn't exist. Re-add in v2.9.0 once we
# pick an audio-capture library (sounddevice or pyaudio) and ship the
# real pipeline.


# ---------------------------------------------------------------------------
# F42 — Sandboxed command executor
# ---------------------------------------------------------------------------
def sandboxed_exec(cmd: list[str], *, timeout_s: int = 30) -> dict:
    """Execute `cmd` inside the OS's available sandbox:
      Linux  → bubblewrap (bwrap)
      macOS  → sandbox-exec
      Windows → not supported; returns skipped.
    """
    import sys
    import shutil
    import subprocess
    if sys.platform.startswith("linux"):
        bwrap = shutil.which("bwrap")
        if not bwrap:
            return {"status": "skipped",
                     "reason": "bubblewrap (bwrap) not installed"}
        wrapped = [bwrap, "--ro-bind", "/", "/", "--proc", "/proc",
                    "--dev", "/dev", "--unshare-all", "--die-with-parent",
                    "--", *cmd]
    elif sys.platform == "darwin":
        # v2.8.2 M4 — macOS sandbox-exec is deprecated since macOS 13 AND
        # the v2.8.1 profile (allow process-exec + process-fork) provided
        # essentially zero containment. Return skipped with a clear note
        # so callers don't believe they're getting sandboxing.
        return {"status": "skipped",
                 "reason": "macOS sandbox-exec is deprecated and the prior "
                            "profile granted process-exec+fork (no real "
                            "isolation); use a container or App Sandbox."}
    else:
        return {"status": "skipped",
                 "reason": f"sandboxed exec not supported on {sys.platform}"}
    try:
        r = subprocess.run(wrapped, capture_output=True, text=True,
                            timeout=timeout_s)
        return {"status": "ok", "exit": r.returncode,
                 "stdout": r.stdout[:4000], "stderr": r.stderr[:4000]}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except (OSError, FileNotFoundError) as e:
        return {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# F43 — Prompt-injection detector on scan responses
# ---------------------------------------------------------------------------
_PI_PATTERNS = (
    "ignore previous instructions",
    "ignore all previous",
    "you are now",
    "jailbreak",
    "system prompt:",
    "{{system}}",
    "<|im_start|>system",
    "###system",
)


def detect_prompt_injection_in_response(text: str) -> dict:
    """Cheap rule-based scan of a server-controlled response body for known
    prompt-injection patterns. Returns {status, hits}."""
    if not text:
        return {"status": "ok", "hits": []}
    lo = text.lower()
    hits = [p for p in _PI_PATTERNS if p in lo]
    return {"status": "ok", "hits": hits}


# ---------------------------------------------------------------------------
# F44 — Prompt/response cache
# ---------------------------------------------------------------------------
def cached_llm(prompt: str, *, template_version: str = "v1",
                ttl_s: int = 86400, llm_fn: Any = None) -> str | None:
    """Wrap llm_fn with a disk cache keyed on (template_version, prompt_hash)."""
    cache_dir = _home() / "ai_cache"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        cache_dir = None
    key = hashlib.sha256(f"{template_version}::{prompt}".encode()).hexdigest()[:32]
    if cache_dir:
        p = cache_dir / f"{key}.json"
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if time.time() - data.get("ts", 0) < ttl_s:
                    return data.get("response")
            except (OSError, ValueError):
                pass
    if not callable(llm_fn):
        return None
    try:
        resp = llm_fn(prompt)
    except Exception:  # noqa: BLE001
        return None
    if cache_dir and resp is not None:
        try:
            p.write_text(json.dumps({"ts": time.time(), "response": resp}),
                          encoding="utf-8")
        except OSError:
            pass
    return resp


# ---------------------------------------------------------------------------
# F45 — Cheaper-model fallback under budget
# ---------------------------------------------------------------------------
def model_with_budget_fallback(prompt: str, *, budget_cents: float = 5.0,
                                tier_fns: list[tuple[float, Any]] | None = None
                                ) -> tuple[str | None, str]:
    """Try LLMs in order from cheapest first; skip any tier whose per-call
    cost exceeds the remaining budget.

    `tier_fns = [(est_cost_cents, llm_fn), ...]` ordered cheap → expensive.
    Returns (response, which_tier_won)."""
    if not tier_fns:
        return None, "no tiers configured"
    remaining = budget_cents
    for cost, fn in tier_fns:
        if cost > remaining:
            continue
        try:
            resp = fn(prompt)
            if resp:
                return resp, f"tier@{cost}c"
            # Empty/None response counts as a soft failure — fall through
            # to the next tier without charging the full cost.
            remaining -= cost / 10
            continue
        except Exception:  # noqa: BLE001
            # v2.8.2 L5 — failed calls charge a 10% "penalty" rather than
            # the full cost so a string of failures doesn't immediately
            # exhaust the budget. Document the intent explicitly.
            remaining -= cost / 10
            continue
    return None, "all tiers exhausted budget or failed"


# ---------------------------------------------------------------------------
# F47 — SOC2 / HIPAA / PCI auto-control mapper
# ---------------------------------------------------------------------------
def auto_control_mapper(report, framework: str = "soc2") -> dict:
    """Map findings to framework controls; identify uncovered controls
    (gap analysis). LLM-free — uses existing compliance_map.json + a
    minimal hardcoded control catalogue."""
    framework = framework.lower()
    try:
        from . import tags as _t
        cmap = _t._load_compliance() or {}
    except (ImportError, AttributeError):
        cmap = {}
    # v2.8.2 H5 — SOC2 maps to the AICPA Trust Services Criteria
    # (CC1.x-CC9.x + A/PI/C/P series), NOT to NIST 800-53. v2.8.1 was
    # silently labelling NIST controls as SOC2 controls. We don't yet
    # have a SOC2 control catalogue in compliance_map.json; surface that
    # gap explicitly to the caller rather than returning wrong data.
    if framework == "soc2":
        return {"framework": "soc2", "controls_triggered": {},
                 "control_count": 0,
                 "note": "SOC2 TSC mapping not yet shipped; awaiting "
                          "compliance_map.json `soc2` field. v2.9.0 "
                          "candidate."}
    # v2.8.2 L9 — filter None from controls before keying triggered.
    triggered: dict[str, list[str]] = {}
    for r in report.results:
        if not r.findings:
            continue
        m = cmap.get(r.check_id) or {}
        controls: list[str] = []
        if framework == "hipaa":
            v = m.get("nist_800_53")
            if v:
                controls = [v]
        elif framework == "pci":
            v = m.get("pci_dss")
            if v:
                controls = [v]
        elif framework == "iso27001":
            v = m.get("iso_27001")
            if v:
                controls = [v]
        for c in controls:
            if c is None:
                continue
            triggered.setdefault(c, []).append(r.check_id)
    return {"framework": framework, "controls_triggered": triggered,
             "control_count": len(triggered)}


# ---------------------------------------------------------------------------
# F48 — Anomaly drift alert
# ---------------------------------------------------------------------------
def anomaly_drift_alert(target: str, current_score: int, *,
                         lookback_n: int = 30) -> dict:
    """Compute mean+stdev of risk_score across the last N scans of target;
    flag if current_score is >2 stdev outside the mean."""
    try:
        from . import history as _h
    except ImportError:
        return {"status": "skipped", "reason": "history module missing"}
    scores: list[int] = []
    try:
        for ent in _h.list_snapshots(target)[:lookback_n]:
            p = _h.snapshot_path(target, ent.get("ts"))
            if p and p.exists():
                try:
                    snap = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(snap.get("risk_score"), int):
                        scores.append(snap["risk_score"])
                except (OSError, ValueError):
                    continue
    except AttributeError:
        return {"status": "skipped", "reason": "snapshot helpers missing"}
    if len(scores) < 5:
        return {"status": "skipped", "reason": f"only {len(scores)} samples; need 5+"}
    mean = sum(scores) / len(scores)
    var = sum((s - mean) ** 2 for s in scores) / len(scores)
    stdev = var ** 0.5
    z = (current_score - mean) / stdev if stdev else 0.0
    return {
        "status": "ok", "mean": mean, "stdev": stdev, "z": z,
        "anomaly": abs(z) > 2.0,
        "current": current_score, "n": len(scores),
    }


# ---------------------------------------------------------------------------
# F71 (v2.8.3) — Generate WAF rule for a finding
# ---------------------------------------------------------------------------
def generate_waf_rule_for_finding(finding: dict, *, target_waf: str = "cloudflare",
                                     llm_fn: Any = None) -> dict:
    """v2.8.3 F71 — LLM-generated WAF rule for a finding that isn't in
    the pre-authored `waf_rules.py` dictionary.

    target_waf: "cloudflare" (Expression Language) or "modsecurity"
    (SecRule). Other values return a skipped status.

    llm_fn signature: `(prompt: str) -> str`. If absent, falls back
    to ai_assist.assist when available.
    """
    target_waf = (target_waf or "cloudflare").lower()
    if target_waf not in ("cloudflare", "modsecurity"):
        return {"status": "skipped",
                 "reason": f"unsupported target_waf={target_waf!r}; use cloudflare|modsecurity"}
    if not isinstance(finding, dict):
        return {"status": "error", "reason": "finding must be a dict"}
    if llm_fn is None:
        try:
            from . import ai_assist as _aa
            llm_fn = getattr(_aa, "assist", None)
        except ImportError:
            llm_fn = None
    if not callable(llm_fn):
        return {"status": "skipped",
                 "reason": "no llm_fn available (set OPENAI_API_KEY + ai_assist)"}
    syntax_hint = (
        "Cloudflare Expression Language — single line starting with "
        "`(http.request.uri.path matches \"...\" and ...)`"
        if target_waf == "cloudflare"
        else "ModSecurity SecRule — single rule line starting with "
              "`SecRule ARGS \"...\" \"id:1234,phase:2,deny,log,...\"`"
    )
    prompt = (
        f"Generate a {target_waf.upper()} WAF rule that blocks the attack "
        f"pattern described by this wpsecscan finding.\n\n"
        f"Title: {finding.get('title', '')!r}\n"
        f"Evidence: {(finding.get('evidence') or '')[:1000]!r}\n"
        f"check_id: {finding.get('check_id', '')!r}\n"
        f"severity: {finding.get('severity', '')!r}\n\n"
        f"Output ONLY the rule itself, no markdown fence, no commentary. "
        f"Syntax: {syntax_hint}"
    )
    try:
        rule = (llm_fn(prompt) or "").strip()
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": str(e)}
    if not rule:
        return {"status": "skipped", "reason": "LLM returned empty"}
    return {"status": "ok", "target_waf": target_waf, "rule": rule}
