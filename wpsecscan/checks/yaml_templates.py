"""#9 — YAML template runner check.

Discovers and runs every `*.yaml` / `*.yml` template in
`~/.wpsecscan/templates/`. Templates use a subset of nuclei's grammar
(see wpsecscan/template_engine.py for the supported schema).

Optional dep: PyYAML. If not installed, the check emits an info finding
explaining how to enable.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    try:
        from .. import template_engine as _te
    except ImportError:
        return [Finding(
            severity="info",
            title="YAML templates skipped (template_engine module missing)",
            evidence="Internal error: wpsecscan.template_engine couldn't be imported.",
            remediation="No action.",
            url=ctx["target"],
        )]

    if not _te._has_yaml():
        findings.append(Finding(
            severity="info",
            title="YAML templates skipped (PyYAML not installed)",
            evidence=(
                "Drop YAML templates into ~/.wpsecscan/templates/ to extend coverage "
                "without writing Python. nuclei-style schema (subset) — see "
                "wpsecscan/template_engine.py docstring for the supported fields.\n\n"
                "Install: `pip install pyyaml`"
            ),
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    templates = _te.list_templates()
    if not templates:
        findings.append(Finding(
            severity="info",
            title="YAML templates skipped (none found in ~/.wpsecscan/templates/)",
            evidence=("PyYAML is installed but no .yaml/.yml templates were found. Drop "
                       "nuclei-style templates in the templates directory to extend coverage."),
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    step(f"running {len(templates)} YAML template(s)...")
    template_findings = await _te.run_all_templates(client, ctx)
    if not template_findings:
        findings.append(Finding(
            severity="info",
            title=f"YAML templates — {len(templates)} template(s) ran, none matched",
            evidence=f"Templates probed: {', '.join(p.stem for p in templates[:10])}",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    findings.extend(template_findings)
    return findings
