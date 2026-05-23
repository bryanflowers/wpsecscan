"""#11 (from nuclei) — workflow chaining.

A workflow is a YAML file that runs other templates conditionally based on
prior matches. Example:

    id: wp-deep-workflow
    info:
      name: WordPress deep-dive workflow
      description: only run plugin-specific templates if WP is detected
    workflows:
      - template: detect-wordpress.yaml
        subtemplates:
          - tags: wordpress,plugin
          - tags: wordpress,critical

Workflow load order:
  1. Run `template` (must produce >= 1 match to proceed)
  2. For each `subtemplate`, find matching templates by id, file path,
     or `tags` filter from the info block
  3. Run them against the same target
  4. Aggregate all findings
"""
from __future__ import annotations

from pathlib import Path

from .http import Client
from .models import Finding


def workflows_dir() -> Path:
    from . import history as _h
    return Path(_h._home()) / "workflows"


def list_workflows() -> list[Path]:
    d = workflows_dir()
    if not d.exists():
        return []
    return sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")))


def _load_yaml(path: Path):
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _matches_filter(tmpl: dict, filt: dict) -> bool:
    """Return True if `tmpl` satisfies the subtemplate filter (`tags`/`id`)."""
    info = tmpl.get("info") or {}
    if "id" in filt and tmpl.get("id") == filt["id"]:
        return True
    if "tags" in filt:
        wanted = {t.strip() for t in str(filt["tags"]).split(",") if t.strip()}
        actual = set()
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        for t in tags:
            actual.add(str(t).strip())
        if wanted & actual:
            return True
    return False


async def run_workflow(workflow: dict, client: Client, ctx: dict) -> list[Finding]:
    """Execute one workflow document. Returns findings from every matched sub-template."""
    from . import template_engine as _te
    findings: list[Finding] = []
    blocks = workflow.get("workflows") or []
    if not blocks:
        return findings

    # Build an index of all available templates so we can filter by tag
    all_tmpls: list[tuple[Path, dict]] = []
    for p in _te.list_templates():
        t = _te._load_template(p)
        if t:
            all_tmpls.append((p, t))

    for block in blocks:
        entry_path = block.get("template")
        if not entry_path:
            continue
        entry = _load_yaml(_te.templates_dir() / entry_path)
        if not entry:
            continue
        entry_findings = await _te.run_template(entry, client, ctx)
        if not entry_findings:
            continue  # entry didn't match → skip subtemplates
        findings.extend(entry_findings)

        for sub_filter in (block.get("subtemplates") or []):
            for _p, tmpl in all_tmpls:
                if _matches_filter(tmpl, sub_filter):
                    findings.extend(await _te.run_template(tmpl, client, ctx))
    return findings


async def run_all_workflows(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    for wf_path in list_workflows():
        wf = _load_yaml(wf_path)
        if not wf:
            continue
        try:
            findings.extend(await run_workflow(wf, client, ctx))
        except Exception:  # noqa: BLE001
            continue
    return findings
