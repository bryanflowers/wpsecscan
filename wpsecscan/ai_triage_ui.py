"""Advanced AI options panel — GUI + CLI for ai_triage.AITriageSettings.

Round-65 Group C — UI surface for the 10 AI-triage toggles.
"""
from __future__ import annotations

import tkinter as tk
from dataclasses import fields
from tkinter import ttk, messagebox
from typing import Any

from . import ai_assist, ai_triage


# ============================================================
# GUI panel
# ============================================================


def open_advanced_ai_options(parent: tk.Misc) -> None:
    """Open the Advanced AI options Toplevel."""
    win = tk.Toplevel(parent)
    win.title("Advanced AI options")
    win.geometry("620x680")

    settings = ai_triage.AITriageSettings.load()
    configured = ai_assist.is_configured()

    # Banner: configured status
    banner = ttk.Frame(win, padding=10)
    banner.pack(fill="x")
    if configured:
        ttk.Label(
            banner,
            text="✓ LLM backend configured (OpenAI / Anthropic / Ollama detected).",
            foreground="#2e7d32",
        ).pack(anchor="w")
    else:
        ttk.Label(
            banner,
            text="⚠ No LLM backend detected. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, "
                 "or install Ollama before turning these on.",
            foreground="#e64a19",
            wraplength=580,
        ).pack(anchor="w")

    ttk.Separator(win).pack(fill="x", padx=10)

    # Scrollable body for the 10 toggles
    canvas = tk.Canvas(win, highlightthickness=0)
    scrollbar = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
    body = ttk.Frame(canvas)
    body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=body, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True, padx=10, pady=4)
    scrollbar.pack(side="right", fill="y")

    # Build toggles
    vars_: dict[str, Any] = {}
    text_vars: dict[str, tk.StringVar] = {}

    def _toggle(field: str, label: str, description: str) -> None:
        frame = ttk.Frame(body, padding=(6, 8))
        frame.pack(fill="x")
        v = tk.BooleanVar(value=bool(getattr(settings, field)))
        cb = ttk.Checkbutton(frame, text=label, variable=v)
        cb.pack(anchor="w")
        ttk.Label(frame, text=description, foreground="#666",
                  wraplength=560, font=("TkDefaultFont", 8)).pack(anchor="w", padx=22)
        vars_[field] = v
        ttk.Separator(body).pack(fill="x")

    def _text_input(field: str, label: str) -> None:
        frame = ttk.Frame(body, padding=(28, 4))
        frame.pack(fill="x")
        ttk.Label(frame, text=label, width=28).pack(side="left")
        v = tk.StringVar(value=str(getattr(settings, field)))
        text_vars[field] = v
        ttk.Entry(frame, textvariable=v, width=32).pack(side="left")

    _toggle("severity_auto_tuner", "C1 — Severity auto-tuner",
            "Re-rank findings by site-specific real-world risk (LLM call per scan).")

    _toggle("duplicate_collapser", "C2 — Duplicate / sibling collapser",
            "Group N findings into K root causes (e.g. 12 missing-header findings → 1 'edge config drift' parent).")

    _toggle("false_positive_predictor", "C3 — False-positive predictor",
            "LLM scores how likely each finding is a false positive given the stack. "
            "Auto-hides findings above the threshold.")
    _text_input("fp_auto_hide_threshold", "  Auto-hide threshold (0.0-1.0)")

    _toggle("exec_brief_generator", "C4 — Plain-English exec brief generator",
            "Writes the 1-page exec summary at the top of the report, tailored to the audience.")
    _text_input("exec_brief_audience", "  Audience (ceo/cto/auditor/dev)")

    _toggle("remediation_step_generator", "C5 — Remediation step-generator",
            "LLM writes copy-paste fix commands for YOUR stack on every finding (heavy LLM cost).")
    _text_input("remediation_stack_profile", "  Stack (wp_engine/self_hosted/kubernetes/cpanel)")

    _toggle("timeline_narrator", "C6 — Forensics timeline narrator",
            "Narrates what attackers likely did during an incident (requires forensics module + log files).")

    _toggle("business_impact_estimator", "C7 — Risk-of-doing-nothing estimator",
            "Estimates business-impact $ if top-3 findings get exploited (needs revenue + tx context).")
    _text_input("estimated_annual_revenue_usd", "  Annual revenue (USD)")
    _text_input("estimated_transactions_per_day", "  Transactions / day")

    _toggle("ticket_autogen", "C8 — Auto-triage Jira / Linear tickets",
            "LLM splits findings into well-shaped tickets with acceptance criteria.")
    _text_input("ticket_destination", "  Destination (jira/linear/github_issue)")

    _toggle("realtime_kev_correlation", "C9 — Real-time CISA-KEV correlation",
            "For each finding with a CVE: cross-reference CISA KEV + recent attacker chatter.")

    _toggle("conversational_qa", "C10 — Conversational scan-result Q&A",
            "Chat over the scan report. Off by default — significant LLM call volume.")

    # Save + close buttons
    btn_row = ttk.Frame(win, padding=10)
    btn_row.pack(fill="x")

    def _save():
        new = ai_triage.AITriageSettings()
        for field_name, var in vars_.items():
            setattr(new, field_name, bool(var.get()))
        for field_name, sv in text_vars.items():
            raw = sv.get().strip()
            field_type = ai_triage.AITriageSettings.__dataclass_fields__[field_name].type
            try:
                if field_type is float or field_type == "float":
                    setattr(new, field_name, float(raw or 0))
                elif field_type is int or field_type == "int":
                    setattr(new, field_name, int(raw or 0))
                else:
                    setattr(new, field_name, raw)
            except ValueError:
                messagebox.showerror("Invalid input", f"{field_name}: {raw!r} is not valid")
                return
        new.save()
        messagebox.showinfo(
            "Saved",
            "Advanced AI options saved. Re-run a scan to apply.\n"
            "Note: each enabled feature adds 1-5 LLM calls per scan."
        )
        win.destroy()

    ttk.Button(btn_row, text="Save", command=_save).pack(side="right", padx=4)
    ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="right")
    ttk.Button(btn_row, text="Disable all",
               command=lambda: [v.set(False) for v in vars_.values()]).pack(side="left")


# ============================================================
# CLI: `wpsecscan ai-options ...`
# ============================================================


def cli_get(field: str) -> str:
    """Return the current value of a setting as a string."""
    s = ai_triage.AITriageSettings.load()
    if field not in s.__dataclass_fields__:
        return f"unknown field: {field}"
    return str(getattr(s, field))


def cli_set(field: str, value: str) -> str:
    """Set + persist a single field. Returns 'ok' or error string."""
    s = ai_triage.AITriageSettings.load()
    if field not in s.__dataclass_fields__:
        return f"unknown field: {field}"
    decl = s.__dataclass_fields__[field]
    try:
        if decl.type is bool or decl.type == "bool":
            setattr(s, field, value.lower() in ("1", "true", "yes", "on"))
        elif decl.type is float or decl.type == "float":
            setattr(s, field, float(value))
        elif decl.type is int or decl.type == "int":
            setattr(s, field, int(value))
        else:
            setattr(s, field, value)
        s.save()
        return "ok"
    except (ValueError, TypeError) as e:
        return f"invalid value: {e}"


def cli_list() -> str:
    """Print all settings + their current values."""
    s = ai_triage.AITriageSettings.load()
    lines = ["Advanced AI options:"]
    for f in fields(s):
        lines.append(f"  {f.name:<35} = {getattr(s, f.name)}")
    ok, reason = ai_triage.is_available()
    lines.append("")
    lines.append(f"AI-triage available: {ok}" + (f"  ({reason})" if not ok else ""))
    return "\n".join(lines)
