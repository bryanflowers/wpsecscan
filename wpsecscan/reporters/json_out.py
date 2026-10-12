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
    # Both best-effort — if the integration fails (offline, etc.) the data is
    # left out, but the failure is recorded (`kev_error` / `epss_error`) so a
    # consumer can tell "not checked" from "checked, none".
    cves_in_report = _collect_cves(report)
    kev_hits: set[str] = set()
    epss_map: dict = {}
    kev_error: str | None = None
    epss_error: str | None = None
    if cves_in_report:
        try:
            from ..integrations import cisa_kev as _kev
            kev_set = _kev.load_kev_set()
            if kev_set:
                kev_hits = {c for c in cves_in_report if c in kev_set}
            else:
                kev_error = "KEV catalogue unavailable (empty set; feed unreachable and no cache)"
        except Exception as e:  # noqa: BLE001
            kev_error = f"{type(e).__name__}: {e}"
        try:
            from ..integrations import epss as _epss
            epss_map = _epss.lookup_scores(cves_in_report)
            if not epss_map:
                epss_error = "EPSS returned no scores (feed unreachable or CVEs not yet scored)"
        except Exception as e:  # noqa: BLE001
            epss_error = f"{type(e).__name__}: {e}"
    if kev_hits or epss_map or kev_error or epss_error:
        d["threat_intel"] = {
            # null = KEV not checked (see kev_error); [] = checked, no matches.
            "cisa_kev_actively_exploited": None if kev_error else sorted(kev_hits),
            "epss_scores": epss_map,
        }
        if kev_error:
            d["threat_intel"]["kev_error"] = kev_error
        if epss_error:
            d["threat_intel"]["epss_error"] = epss_error
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


def _sanitise_json_floats(obj):
    """B12 (v2.8.0) — recursively replace NaN/Inf floats with None so
    the emitted JSON is always valid RFC 8259 (which forbids those
    tokens). AI scores and perf metrics occasionally produce NaN; the
    pre-fix `json.dumps(...)` emitted the non-standard literals
    `NaN`/`Infinity` and most strict JSON parsers (jq, JSONLines
    consumers, ES bulk loaders) rejected the file."""
    import math as _m
    if isinstance(obj, float):
        return None if (_m.isnan(obj) or _m.isinf(obj)) else obj
    if isinstance(obj, dict):
        return {k: _sanitise_json_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitise_json_floats(v) for v in obj]
    if isinstance(obj, tuple):
        return [_sanitise_json_floats(v) for v in obj]
    return obj


def render(report: ScanReport, *, ascii_only: bool = False) -> str:
    """Render the report as JSON.

    `ascii_only=True` forces `ensure_ascii=True` (Unicode escaped to
    `\\uXXXX`). v2.8.1 B44 — some downstream consumers (legacy log
    shippers, ES bulk loaders running with strict-ASCII codecs) need
    this. The default `False` preserves Unicode for the common case.
    Wire `--json-ascii` in `__main__.py` to pass `ascii_only=True`.
    """
    return json.dumps(
        _sanitise_json_floats(_enrich(report)),
        indent=2, ensure_ascii=ascii_only, allow_nan=False,
    )


def write(report: ScanReport, path: Path, *, ascii_only: bool = False) -> None:
    # v2.8.1 B39 — atomic temp+rename. Pre-fix bare write_text could
    # produce a torn file if the process died mid-write.
    # v2.8.1 B44 — `ascii_only` opt-in passed through to render().
    from . import _atomic_write_text
    _atomic_write_text(path, render(report, ascii_only=ascii_only))
    try:
        from .. import activity as _act
        _act.emit("reporter", f"JSON: {path.name} ({path.stat().st_size // 1024} KB)")
    except (ImportError, OSError):
        pass
