"""#11 — YAML workflow runner check.

Runs every workflow in `~/.wpsecscan/workflows/`. See wpsecscan/workflow.py
for the schema. Workflows let templates chain — an entry template's match
gates the execution of subsequent templates filtered by tag/id.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    from .. import template_engine as _te
    from .. import workflow as _wf

    if not _te._has_yaml():
        findings.append(Finding(
            severity="info",
            title="YAML workflows skipped (PyYAML not installed)",
            evidence="Install pyyaml + drop workflows in ~/.wpsecscan/workflows/ to enable.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    wfs = _wf.list_workflows()
    if not wfs:
        findings.append(Finding(
            severity="info",
            title="No YAML workflows found",
            evidence="Drop workflow.yaml files in ~/.wpsecscan/workflows/ to enable chained template runs.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    step(f"running {len(wfs)} workflow(s)...")
    wf_findings = await _wf.run_all_workflows(client, ctx)
    if not wf_findings:
        findings.append(Finding(
            severity="info",
            title=f"YAML workflows — {len(wfs)} workflow(s) ran, no matches",
            evidence=f"Workflows: {', '.join(p.stem for p in wfs[:5])}",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings
    findings.extend(wf_findings)
    return findings
