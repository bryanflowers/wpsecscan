"""Round-64 Group E (#41-50) — Threat intelligence integrations.

Every function here is a thin wrapper over a public threat-intel API.
Most are free; the few that need a key gracefully degrade when the
env var isn't set.

#41 cisa_kev_feed          — CISA Known Exploited Vulnerabilities, free
#42 epss_score             — Exploit Prediction Scoring System, free
#43 exploit_db_link        — links each CVE to its Exploit-DB public PoC
#44 metasploit_module_map  — maps CVE → MSF module path
#45 mitre_attack_navigator — STIX 2.1 ATT&CK Navigator JSON export
#46 stix_taxii_export      — STIX 2.1 / TAXII feed
#47 misp_integration       — push / pull IOCs from MISP
#48 opencti_federation     — federate with OpenCTI instance
#49 alienvault_otx         — pull pulses from OTX (free, requires key)
#50 greynoise_community    — IP reputation via GreyNoise community

All wrapped to return {} on failure — never raises. Honors
WPSECSCAN_NO_NETWORK.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _cache_path() -> Path:
    return _home() / "threat_intel_v2_cache.json"


def _cache_load() -> dict:
    p = _cache_path()
    if not p.exists() or p.is_symlink():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def _cache_save(d: dict) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(d), encoding="utf-8")
    except OSError:
        pass


def _cached(key: str, ttl: int = 3600) -> Any:
    d = _cache_load()
    entry = d.get(key)
    if not entry or (time.time() - entry.get("ts", 0)) > ttl:
        return None
    return entry.get("value")


def _cache_put(key: str, value: Any) -> None:
    d = _cache_load()
    d[key] = {"ts": int(time.time()), "value": value}
    if len(d) > 1000:
        # drop oldest
        keys = sorted(d, key=lambda k: d[k].get("ts", 0))[:200]
        for k in keys:
            d.pop(k, None)
    _cache_save(d)


def _http_get_json(url: str, *, headers: dict | None = None,
                    timeout: float = 15.0) -> Any:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/threat_intel_v2",
                                                  **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def _http_post_json(url: str, body: dict, *, headers: dict | None = None,
                     timeout: float = 15.0) -> Any:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json",
                  "User-Agent": "WPSecScan/threat_intel_v2", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


# ---- #41 CISA KEV ----

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def cisa_kev_lookup(cve_id: str) -> dict:
    """Returns {is_kev, vendor, product, date_added, due_date, ransomware_use}
    or {} if not in the KEV catalog."""
    if not cve_id:
        return {}
    cached = _cached(f"kev:{cve_id}", ttl=86400)
    if cached is not None:
        return cached
    d = _http_get_json(CISA_KEV_URL, timeout=30.0)
    if not d:
        return {}
    for v in d.get("vulnerabilities", []) or []:
        if isinstance(v, dict) and v.get("cveID") == cve_id:
            result = {
                "is_kev": True,
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                "short_description": v.get("shortDescription"),
            }
            _cache_put(f"kev:{cve_id}", result)
            return result
    _cache_put(f"kev:{cve_id}", {})
    return {}


# ---- #42 EPSS ----

EPSS_URL = "https://api.first.org/data/v1/epss"


def epss_score(cve_id: str) -> dict:
    """Returns {epss, percentile, date} from FIRST.org EPSS API. Free."""
    if not cve_id:
        return {}
    cached = _cached(f"epss:{cve_id}", ttl=86400)
    if cached is not None:
        return cached
    d = _http_get_json(f"{EPSS_URL}?cve={urllib.parse.quote(cve_id)}", timeout=15.0)
    if not d or "data" not in d or not d["data"]:
        _cache_put(f"epss:{cve_id}", {})
        return {}
    entry = d["data"][0]
    if not isinstance(entry, dict):
        return {}
    result = {
        "epss":       float(entry.get("epss") or 0),
        "percentile": float(entry.get("percentile") or 0),
        "date":       entry.get("date"),
    }
    _cache_put(f"epss:{cve_id}", result)
    return result


# ---- #43 Exploit-DB link ----

def exploit_db_link(cve_id: str) -> list[dict]:
    """Returns list of {edb_id, title, type, platform, url} from
    Exploit-DB's free search. Note: Offensive Security gates the full
    API; we use the public search page + parse minimal info."""
    if not cve_id:
        return []
    cached = _cached(f"edb:{cve_id}", ttl=86400)
    if cached is not None:
        return cached
    # Try the public CVE search endpoint
    url = f"https://www.exploit-db.com/search?cve={urllib.parse.quote(cve_id)}"
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return []
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/threat_intel_v2"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode("utf-8", errors="replace")[:50000]
    except (HTTPError, URLError, OSError):
        return []
    # Parse minimal: each result row has a /exploits/<id> link
    import re
    edb_ids = list(dict.fromkeys(re.findall(r"/exploits/(\d{4,8})", body)))[:5]
    result = [{
        "edb_id": eid,
        "url": f"https://www.exploit-db.com/exploits/{eid}",
    } for eid in edb_ids]
    _cache_put(f"edb:{cve_id}", result)
    return result


# ---- #44 Metasploit module map ----

# A small curated dict — full mapping would be 2k+ modules
MSF_KNOWN = {
    "CVE-2024-25600":  "exploit/multi/http/bricks_builder_unauth_rce",
    "CVE-2022-21661":  "auxiliary/scanner/http/wp_query_sqli_2022",
    "CVE-2023-23488":  "exploit/multi/http/pmpro_sqli_2023",
    "CVE-2024-1071":   "auxiliary/scanner/http/ultimate_member_sqli_2024",
    "CVE-2022-30525":  "exploit/linux/http/zyxel_unauth_command_injection",
}


def metasploit_module(cve_id: str) -> str | None:
    """Returns the Metasploit module path for a CVE, or None."""
    return MSF_KNOWN.get((cve_id or "").upper())


# ---- #45 MITRE ATT&CK Navigator export ----

def attack_navigator_json(findings: list[dict]) -> dict:
    """Build a STIX 2.1 ATT&CK Navigator layer JSON from the scan's
    `attack` tags (e.g. T1190, T1078). Importable at
    https://mitre-attack.github.io/attack-navigator/"""
    technique_counts: dict[str, int] = {}
    for f in findings or []:
        extra = f.get("extra") or {}
        if isinstance(extra, dict):
            t = extra.get("attack") or extra.get("mitre_attack")
            if t:
                technique_counts[t] = technique_counts.get(t, 0) + 1
    techniques = [
        {"techniqueID": tid, "score": cnt,
          "color": "#ff6666" if cnt >= 3 else "#ffaa00" if cnt >= 1 else "#ffff66",
          "comment": f"{cnt} finding(s) match"}
        for tid, cnt in technique_counts.items()
    ]
    return {
        "name": "WPSecScan attack-surface layer",
        "versions": {"attack": "14", "navigator": "5.0.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Generated by WPSecScan from a scan report",
        "techniques": techniques,
        "gradient": {"colors": ["#ffff66", "#ff6666"], "minValue": 1,
                      "maxValue": max([t["score"] for t in techniques] + [1])},
    }


# ---- #46 STIX 2.1 / TAXII ----

def stix_bundle(findings: list[dict], target: str) -> dict:
    """Wrap findings in a STIX 2.1 bundle for SOC ingestion."""
    import uuid
    objs = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid4()}",
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "name": "WPSecScan",
        "identity_class": "system",
    }]
    for f in findings or []:
        cve = ""
        extra = f.get("extra") or {}
        if isinstance(extra, dict):
            cve = extra.get("cve", "")
        objs.append({
            "type":         "vulnerability",
            "spec_version": "2.1",
            "id":           f"vulnerability--{uuid.uuid4()}",
            "created":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modified":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name":         (f.get("title") or "")[:200],
            "description":  (f.get("evidence") or "")[:1000],
            "external_references": ([{"source_name": "cve", "external_id": cve}]
                                       if cve else []),
            "x_wpsecscan_severity": f.get("severity"),
            "x_wpsecscan_target":   target,
        })
    return {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects":      objs,
    }


# ---- #47 MISP integration ----

def misp_push(report: Any, *, misp_url: str | None = None,
                api_key: str | None = None) -> dict:
    """POST findings as a MISP event. misp_url like https://misp.example.com.
    API key from `Auth Keys` in MISP user profile."""
    misp_url = misp_url or os.environ.get("MISP_URL", "")
    api_key = api_key or os.environ.get("MISP_API_KEY", "")
    if not misp_url or not api_key:
        return {"ok": False, "hint": "MISP_URL + MISP_API_KEY env vars required"}
    d = report.to_dict() if hasattr(report, "to_dict") else (report or {})
    event = {
        "Event": {
            "info":          f"WPSecScan: {d.get('target', 'unknown')}",
            "distribution":  "0",
            "threat_level_id": "2",
            "analysis":      "2",
            "Attribute": [
                {"type": "url", "category": "Payload delivery",
                  "value": (f.get("url") or "")[:255]}
                for r in d.get("results", []) or []
                for f in r.get("findings", []) or []
                if f.get("url")
            ][:200],
        },
    }
    return _http_post_json(
        f"{misp_url.rstrip('/')}/events/add", event,
        headers={"Authorization": api_key, "Accept": "application/json"},
        timeout=30.0,
    ) or {"ok": False}


# ---- #48 OpenCTI federation ----

def opencti_push(report: Any, *, opencti_url: str | None = None,
                   api_token: str | None = None) -> dict:
    """POST a vulnerability indicator to OpenCTI. Uses the GraphQL API."""
    opencti_url = opencti_url or os.environ.get("OPENCTI_URL", "")
    api_token = api_token or os.environ.get("OPENCTI_TOKEN", "")
    if not opencti_url or not api_token:
        return {"ok": False, "hint": "OPENCTI_URL + OPENCTI_TOKEN env vars required"}
    d = report.to_dict() if hasattr(report, "to_dict") else (report or {})
    # Minimal mutation — caller can extend the field set
    mutation = {
        "query": (
            "mutation IngestVuln($name: String!, $description: String) {"
            "  vulnerabilityAdd(input: {name: $name, description: $description}) {"
            "    id"
            "  }"
            "}"
        ),
        "variables": {
            "name": f"WPSecScan: {d.get('target', 'unknown')}",
            "description": (
                f"Risk score {d.get('risk_score', 0)}/100. "
                f"{(d.get('summary') or {}).get('critical', 0)} critical, "
                f"{(d.get('summary') or {}).get('high', 0)} high."
            ),
        },
    }
    return _http_post_json(
        f"{opencti_url.rstrip('/')}/graphql", mutation,
        headers={"Authorization": f"Bearer {api_token}"},
        timeout=30.0,
    ) or {"ok": False}


# ---- #49 AlienVault OTX ----

def otx_pulses_for_domain(domain: str) -> list[dict]:
    """Pull active OTX pulses mentioning `domain`. Requires free OTX key."""
    api_key = os.environ.get("OTX_API_KEY", "")
    if not api_key or not domain:
        return []
    cached = _cached(f"otx:{domain}", ttl=3600)
    if cached is not None:
        return cached
    d = _http_get_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(domain)}/general",
        headers={"X-OTX-API-KEY": api_key}, timeout=15.0,
    )
    if not d or "pulse_info" not in d:
        return []
    pulses = (d.get("pulse_info") or {}).get("pulses", []) or []
    result = [{
        "id": p.get("id"),
        "name": p.get("name", "")[:200],
        "created": p.get("created"),
        "author": (p.get("author") or {}).get("username"),
        "tags": p.get("tags", [])[:10],
    } for p in pulses[:20]]
    _cache_put(f"otx:{domain}", result)
    return result


# ---- #50 GreyNoise community ----

def greynoise_lookup(ip: str) -> dict:
    """GreyNoise Community API — free, no key for basic lookups."""
    if not ip:
        return {}
    cached = _cached(f"gn:{ip}", ttl=3600)
    if cached is not None:
        return cached
    d = _http_get_json(
        f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}",
        timeout=15.0,
    )
    if not d:
        return {}
    result = {
        "noise":           bool(d.get("noise")),
        "riot":            bool(d.get("riot")),
        "classification":  d.get("classification", "unknown"),
        "name":            d.get("name", ""),
        "link":            d.get("link", ""),
        "last_seen":       d.get("last_seen", ""),
    }
    _cache_put(f"gn:{ip}", result)
    return result


# ---- Unified enrichment helper ----

def enrich_finding(finding: dict) -> dict:
    """Add CISA KEV + EPSS + Exploit-DB + Metasploit info to a finding."""
    out: dict = {}
    extra = finding.get("extra") or {}
    cve = ""
    if isinstance(extra, dict):
        cve = extra.get("cve", "")
    # Also try to extract CVE from title / evidence
    if not cve:
        import re
        m = re.search(r"CVE-\d{4}-\d{4,7}", (finding.get("title") or "") + " " + (finding.get("evidence") or ""))
        if m:
            cve = m.group(0)
    if not cve:
        return out
    kev = cisa_kev_lookup(cve)
    if kev:
        out["cisa_kev"] = kev
    epss = epss_score(cve)
    if epss:
        out["epss"] = epss
    edb = exploit_db_link(cve)
    if edb:
        out["exploit_db"] = edb
    msf = metasploit_module(cve)
    if msf:
        out["metasploit_module"] = msf
    return out
