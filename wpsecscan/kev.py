"""#67 (v2.6.0) — CISA KEV (Known Exploited Vulnerabilities) catalogue.

Pulls the CISA KEV JSON feed (free, no key) + caches at
~/.wpsecscan/kev-catalog.json with a 6-hour TTL. The cached set of
CVE IDs is the basis for KEV-only filtering in the fast-scan path:

  wpsecscan kev URL

runs the standard scan but post-filters findings to those whose
`extra.cve` is in the KEV catalogue. Optimised for the
'is this site actively exploited NOW?' question — a 30-second
sanity check before triage.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

from ._util import home_dir


_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_TTL = 6 * 3600  # 6 hours


def _cache_path() -> Path:
    return home_dir() / "kev-catalog.json"


def _fresh_enough(p: Path) -> bool:
    try:
        return time.time() - p.stat().st_mtime < _CACHE_TTL
    except OSError:
        return False


def fetch_kev_cves(*, force_refresh: bool = False) -> set[str]:
    """Return the set of all CVE IDs in the current CISA KEV catalogue."""
    p = _cache_path()
    if not force_refresh and p.exists() and _fresh_enough(p):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if data:
            return _cves_from(data)
    try:
        with httpx.Client(timeout=20.0,
                           headers={"User-Agent": "WPSecScan/kev"}) as c:
            r = c.get(_KEV_URL)
            r.raise_for_status()
            text = r.text
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return _cves_from(json.loads(text))
    except (httpx.RequestError, httpx.HTTPStatusError, OSError, ValueError):
        # Fall back to whatever's cached, even if stale.
        if p.exists():
            try:
                return _cves_from(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
        return set()


def _cves_from(data: dict) -> set[str]:
    out: set[str] = set()
    for entry in (data.get("vulnerabilities") or []):
        cve = (entry.get("cveID") or "").strip().upper()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


def filter_findings_to_kev(report) -> int:
    """Mutate report.results in-place: drop findings whose extra.cve isn't
    in the KEV catalogue. Returns the number kept."""
    kev = fetch_kev_cves()
    if not kev:
        return 0
    kept = 0
    for r in report.results:
        new_findings = []
        for f in r.findings:
            cve = (f.extra.get("cve") or "").strip().upper() if isinstance(f.extra, dict) else ""
            cves = (f.extra.get("cves") or []) if isinstance(f.extra, dict) else []
            hit_cves = []
            if cve and cve in kev:
                hit_cves.append(cve)
            for c in cves:
                if isinstance(c, str) and c.upper() in kev:
                    hit_cves.append(c.upper())
            if hit_cves:
                f.extra["kev_match"] = sorted(set(hit_cves))
                new_findings.append(f)
                kept += 1
        r.findings = new_findings
    return kept
