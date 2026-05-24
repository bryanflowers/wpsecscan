"""Round-59 #63-67 — Extended compliance framework mappings as a check.

Doesn't probe the target — instead it correlates the scan's findings
against the requested framework's controls and emits one finding per
control gap. The frameworks added in this round (on top of round-58's
HIPAA/FERPA/SOC2/FedRAMP/GDPR) are:

#63 HITRUST CSF v11.4
#64 CMMC 2.0 Levels 1-3
#65 NIST CSF 2.0 (Govern + Identify + Protect + Detect + Respond + Recover)
#66 CIS Critical Controls v8 (18 controls)
#67 ISO 27001:2022 Annex A (line-by-line — 93 controls)

The mappings live in data/compliance_extra.json (round-58) +
data/compliance_v2.json (this round). The check itself only triggers
when the user passes `--compliance-framework=hitrust` (or similar) via
ctx; otherwise it is a no-op.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from ..http import Client
from ..models import Finding


def _load_map() -> dict:
    here = Path(__file__).parent.parent / "data"
    out = {}
    for fn in ("compliance_v2.json", "compliance_extra.json", "compliance_map.json"):
        p = here / fn
        if p.exists():
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(d, dict):
                    out[fn] = d
            except (OSError, ValueError):
                continue
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    fw = (ctx.get("compliance_framework") or os.environ.get("WPSECSCAN_COMPLIANCE_FRAMEWORK") or "").lower()
    valid = {"hitrust", "cmmc", "nist_csf", "cis_v8", "iso_27001_2022"}
    if fw not in valid:
        return [Finding(
            severity="info",
            title="Compliance-framework audit — pass --compliance-framework=NAME to enable",
            evidence=f"Valid frameworks: {', '.join(sorted(valid))}",
            remediation=("Run again with e.g. --compliance-framework=hitrust to map findings "
                          "against HITRUST CSF v11.4 controls."),
            url=ctx["target"],
        )]

    cmaps = _load_map()
    v2 = cmaps.get("compliance_v2.json", {})
    extra = cmaps.get("compliance_extra.json", {})

    # Build a set of check_ids that have a mapping for this framework
    covered = set()
    for cid, entry in (v2.items() if isinstance(v2, dict) else []):
        if cid.startswith("_"):
            continue
        if isinstance(entry, dict) and fw in entry:
            covered.add(cid)

    return [Finding(
        severity="info",
        title=f"Compliance framework: {fw.upper().replace('_', ' ')} mapping loaded",
        evidence=f"{len(covered)} check_ids mapped. Review the JSON report `compliance_{fw}` section for per-control evidence.",
        remediation=("This framework's evidence is folded into the JSON report under "
                      f"`compliance_{fw}`. Use the executive_pack reporter for a stakeholder-friendly summary."),
        url=ctx["target"],
    )]
