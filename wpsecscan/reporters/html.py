from __future__ import annotations

import json
import sys
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanReport


def _template_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent.parent / "data"


def _load_guidance() -> dict:
    """Load the quick_fixes.json doc — exposes both `fixes` and `verify` sections."""
    f = _template_dir() / "quick_fixes.json"
    if not f.exists():
        return {"fixes": {}, "verify": {}}
    try:
        data = json.loads(f.read_text(encoding="utf-8")) or {}
        return {
            "fixes": data.get("fixes", {}) or {},
            "verify": data.get("verify", {}) or {},
        }
    except (OSError, json.JSONDecodeError):
        return {"fixes": {}, "verify": {}}


def _substitute(template: str, target: str) -> str:
    """Substitute {target} and {host} in verification command templates."""
    from urllib.parse import urlparse
    host = urlparse(target).hostname or target
    return template.replace("{target}", target.rstrip("/")).replace("{host}", host)


def _build_check_tags() -> dict:
    """Load all per-check OWASP/ATT&CK tag mappings (template-friendly dict)."""
    from .. import tags as _tags
    return _tags._load()


def _build_compliance() -> dict:
    """Load per-check PCI-DSS / NIST 800-53 / ISO 27001 mappings."""
    from .. import tags as _tags
    return _tags._load_compliance()


def _build_confidence_map(report: ScanReport) -> dict:
    """Return {(check_id, finding_index): 'low'|'medium'|'high'} for every finding."""
    from .. import confidence as _conf
    waf_detected = any(
        ("WAF" in (f.title or "") or "CDN detected" in (f.title or ""))
        for r in report.results if r.check_id == "waf"
        for f in r.findings
    )
    out: dict = {}
    for r in report.results:
        for i, f in enumerate(r.findings):
            out[(r.check_id, i)] = _conf.compute_confidence(f, r.check_id, waf_detected=waf_detected)
    return out


def _build_playbooks_for_report(report: ScanReport) -> dict:
    """Return {check_id: [(field, label, content), ...]} for every check that
    has a playbook AND produced at least one finding in this report."""
    from .. import playbook as _pb
    out: dict = {}
    seen_ids = {r.check_id for r in report.results if r.findings}
    for cid in seen_ids:
        raw = _pb.get_playbook(cid)
        if not raw:
            continue
        subst = _pb.substitute(raw, report.target)
        out[cid] = _pb.ordered_buckets(subst)
    return out


def render(report: ScanReport) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_template_dir())),
        autoescape=select_autoescape(enabled_extensions=("html", "j2")),
    )
    tmpl = env.get_template("report.html.j2")
    guidance = _load_guidance()
    # Pre-substitute {target}/{host} placeholders so the template stays simple
    verify_for_target = {
        cid: [_substitute(line, report.target) for line in lines]
        for cid, lines in guidance["verify"].items()
    }
    from ..risk import risk_tier, risk_label, risk_grade
    score = report.risk_score
    conf_map = _build_confidence_map(report)
    # Jinja can't easily handle tuple keys — flatten to "check_id::idx" strings
    conf_flat = {f"{cid}::{i}": v for (cid, i), v in conf_map.items()}
    # D4: WAF rules per check
    from .. import waf_rules as _wr
    from .. import recommend as _rec
    waf_rules_map = {r.check_id: _wr.get_rule(r.check_id) for r in report.results if _wr.get_rule(r.check_id)}
    recommendations = _rec.recommendations_for(report)
    # E2 heatmap — render once, embed inline
    try:
        from .. import heatmap as _hm
        heatmap_svg = _hm.render_svg(report, _build_check_tags())
    except (ImportError, ValueError, TypeError, KeyError):
        heatmap_svg = ""
    return tmpl.render(
        report=report,
        quick_fixes=guidance["fixes"],
        verify_commands=verify_for_target,
        exploit_playbooks=_build_playbooks_for_report(report),
        check_tags=_build_check_tags(),
        compliance=_build_compliance(),
        confidence=conf_flat,
        waf_rules=waf_rules_map,
        recommendations=recommendations,
        risk_score=score,
        risk_tier=risk_tier(score),
        risk_label=risk_label(score),
        risk_grade=risk_grade(score),
        heatmap_svg=heatmap_svg,
    )


def write(report: ScanReport, path: Path) -> None:
    path.write_text(render(report), encoding="utf-8")
    try:
        from .. import activity as _act
        _act.emit("reporter", f"HTML: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
