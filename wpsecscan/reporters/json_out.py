from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .. import __version__ as _scanner_version
from .. import confidence as _confidence
from .. import tags as _tags
from ..models import ScanReport

# Bump when a breaking field rename / removal lands. Additive changes
# don't require a bump.
JSON_SCHEMA_VERSION = 1


def _collect_cves(report: ScanReport) -> list[str]:
    """Extract every CVE ID mentioned in finding titles + extras."""
    import re
    cves: set[str] = set()
    for r in report.results:
        for f in r.findings:
            blob = f"{f.title} {f.evidence}"
            for m in re.findall(r"\bCVE-\d{4}-\d{4,}\b", blob):
                cves.add(m)
            extra = getattr(f, "extra", {}) or {}
            if isinstance(extra.get("cve"), str):
                cves.add(extra["cve"])
            if isinstance(extra.get("cves"), list):
                cves.update(x for x in extra["cves"] if isinstance(x, str))
    return sorted(cves)


def _enrich(report: ScanReport) -> dict:
    """ScanReport.to_dict() + per-finding confidence + per-check tags so the
    JSON consumer sees the same enrichment the HTML/console reporters do."""
    waf_detected = any(
        ("WAF" in (f.title or "") or "CDN detected" in (f.title or ""))
        for r in report.results if r.check_id == "waf"
        for f in r.findings
    )
    d = report.to_dict()
    # Stamp schema + scanner version so downstream consumers can branch
    # on the JSON shape across releases.
    d["_meta"] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "scanner_version": _scanner_version,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    from ..risk import risk_grade
    d["risk_grade"] = risk_grade(d.get("risk_score", 0))
    # C1+C2: enrich every CVE with KEV-actively-exploited badge + EPSS percentile.
    # Both best-effort — if the integration fails (offline, etc.) we leave the data out.
    cves_in_report = _collect_cves(report)
    kev_hits: set[str] = set()
    epss_map: dict = {}
    if cves_in_report:
        try:
            from ..integrations import cisa_kev as _kev
            kev_set = _kev.load_kev_set()
            kev_hits = {c for c in cves_in_report if c in kev_set}
        except Exception:  # noqa: BLE001
            pass
        try:
            from ..integrations import epss as _epss
            epss_map = _epss.lookup_scores(cves_in_report)
        except Exception:  # noqa: BLE001
            pass
    if kev_hits or epss_map:
        d["threat_intel"] = {
            "cisa_kev_actively_exploited": sorted(kev_hits),
            "epss_scores": epss_map,
        }
    # Round-56: embed the activity-feed timeline so a replay of this report
    # can show every feature that fired during the original scan.
    try:
        from .. import activity as _act
        d["activity_log"] = _act.to_list()
    except ImportError:
        pass
    for r_dict, r in zip(d["results"], report.results):
        tg = _tags.get_tags(r.check_id)
        if tg:
            r_dict["tags"] = {
                "owasp": tg.get("owasp"),
                "owasp_label": tg.get("owasp_label"),
                "attack": tg.get("attack"),
                "attack_label": tg.get("attack_label"),
            }
        cm = _tags.get_compliance(r.check_id)
        if cm:
            r_dict["compliance"] = {
                "pci_dss": cm.get("pci_dss"),
                "nist_800_53": cm.get("nist_800_53"),
                "iso_27001": cm.get("iso_27001"),
            }
        for f_dict, f in zip(r_dict["findings"], r.findings):
            f_dict["confidence"] = _confidence.compute_confidence(
                f, r.check_id, waf_detected=waf_detected
            )
    return d


def render(report: ScanReport) -> str:
    return json.dumps(_enrich(report), indent=2, ensure_ascii=False)


def write(report: ScanReport, path: Path) -> None:
    path.write_text(render(report), encoding="utf-8")
    try:
        from .. import activity as _act
        _act.emit("reporter", f"JSON: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
