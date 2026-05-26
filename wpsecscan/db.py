"""Vulnerability database — Wordfence Intelligence v2.

Downloads the full WP vuln DB (~10 MB, ~15k entries) and caches it under
%USERPROFILE%\\.wpsecscan\\vuln-db.json. Refreshes weekly by default.

Also ships an embedded fallback DB so the scanner works offline on first launch.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import httpx

WORDFENCE_URLS = (
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner",
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production",
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner",
)

# Round-63: our nightly-aggregated multi-source feed. The bryanflowers
# canonical instance is updated daily at 02:00 UTC by .github/workflows/
# cve-feed.yml; forks should override via WPSECSCAN_AGGREGATED_FEED_URL.
AGGREGATED_FEED_URL = (
    "https://raw.githubusercontent.com/bryanflowers/wpsecscan/"
    "data-feed/vuln-db.json"
)
STALE_AFTER_SECONDS = 7 * 24 * 3600  # 1 week


def cache_dir() -> Path:
    base = os.environ.get("WPSECSCAN_HOME") or (
        Path.home() / ".wpsecscan"
    )
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def cache_path() -> Path:
    return cache_dir() / "vuln-db.json"


def embedded_fallback_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data" / "plugin_cves.json"
    return Path(__file__).resolve().parent / "data" / "plugin_cves.json"


@dataclass
class Vuln:
    slug: str
    type: str            # "plugin" | "theme" | "core"
    title: str
    severity: str        # info|low|medium|high|critical
    cve: str
    cvss: float | None
    fixed_in: str        # version that fixes it; "" if unpatched
    affected_from: str   # "" or version
    affected_to: str     # "" or version (exclusive iff to_inclusive=False)
    to_inclusive: bool
    references: list[str]
    description: str = ""

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return d


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _parse_wordfence_entry(uuid: str, entry: dict) -> list[Vuln]:
    """Each Wordfence entry can affect multiple software pieces — flatten."""
    title = entry.get("title") or "(no title)"
    cve_list = []
    refs: list[str] = []
    for r in entry.get("references") or []:
        # references can be list of dicts or list of strings depending on version
        if isinstance(r, dict):
            url = r.get("url") or r.get("ref")
            if url:
                refs.append(url)
        elif isinstance(r, str):
            refs.append(r)
    for c in entry.get("cve") or []:
        if isinstance(c, str):
            cve_list.append(c)
    cvss_obj = entry.get("cvss") or {}
    try:
        score = float(cvss_obj.get("score")) if cvss_obj.get("score") else None
    except (TypeError, ValueError):
        score = None
    severity = _cvss_to_severity(score)
    description = entry.get("description") or ""

    out: list[Vuln] = []
    for sw in entry.get("software") or []:
        sw_type = (sw.get("type") or "").lower()
        slug = (sw.get("slug") or "").lower()
        if not slug or sw_type not in ("plugin", "theme", "core"):
            continue
        ranges = (sw.get("affected_versions") or {})
        # Wordfence schema variant: affected_versions can be dict {key: range} or list
        version_ranges: list[dict] = []
        if isinstance(ranges, dict):
            inner = ranges.get("versions")
            if isinstance(inner, list):
                version_ranges = inner
            else:
                version_ranges = list(ranges.values()) if ranges else []
        elif isinstance(ranges, list):
            version_ranges = ranges

        if not version_ranges:
            # No version info — treat as "all versions" with no fixed_in
            out.append(Vuln(
                slug=slug, type=sw_type, title=title, severity=severity,
                cve=cve_list[0] if cve_list else uuid,
                cvss=score, fixed_in="", affected_from="", affected_to="",
                to_inclusive=False, references=refs, description=description,
            ))
            continue
        for vr in version_ranges:
            if not isinstance(vr, dict):
                continue
            fixed_in = (sw.get("patched_versions") or [""])[0] if isinstance(sw.get("patched_versions"), list) else ""
            to_v = vr.get("to_version") or ""
            to_inc = bool(vr.get("to_inclusive", False))
            from_v = vr.get("from_version") or ""
            if to_v and not to_inc and not fixed_in:
                # Common Wordfence shape: vulnerable for everything *less than* to_version
                fixed_in = to_v
            out.append(Vuln(
                slug=slug, type=sw_type, title=title, severity=severity,
                cve=cve_list[0] if cve_list else uuid,
                cvss=score, fixed_in=fixed_in,
                affected_from=from_v, affected_to=to_v, to_inclusive=to_inc,
                references=refs, description=description,
            ))
    return out


def normalize_wordfence(raw: dict) -> list[Vuln]:
    """Flatten Wordfence's dict-of-vulns into a list of Vuln rows."""
    out: list[Vuln] = []
    if not isinstance(raw, dict):
        return out
    for uuid, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        out.extend(_parse_wordfence_entry(uuid, entry))
    return out


def normalize_legacy(raw: dict) -> list[Vuln]:
    """Convert the old hand-curated plugin_cves.json shape to Vuln rows."""
    out: list[Vuln] = []
    for v in (raw.get("vulns") or []):
        out.append(Vuln(
            slug=(v.get("slug") or "").lower(),
            type="plugin",
            title=v.get("title") or "(no title)",
            severity=v.get("severity") or "medium",
            cve=v.get("cve") or "",
            cvss=None,
            fixed_in=v.get("fixed_in") or "",
            affected_from="", affected_to=v.get("fixed_in") or "",
            to_inclusive=False,
            references=[],
            description=v.get("remediation") or "",
        ))
    return out


def load_local() -> tuple[list[Vuln], int, str]:
    """Return (vulns, age_seconds, source). Source ∈ {"cache","embedded"}."""
    cp = cache_path()
    if cp.exists():
        try:
            data = json.loads(cp.read_text(encoding="utf-8"))
            age = int(time.time() - cp.stat().st_mtime)
            if isinstance(data, dict) and data.get("_format") == "wpsecscan/normalized-v1":
                rows = [Vuln(**v) for v in data.get("vulns", [])]
                return rows, age, "cache"
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    # embedded fallback
    fb = embedded_fallback_path()
    if fb.exists():
        try:
            data = json.loads(fb.read_text(encoding="utf-8"))
            rows = normalize_legacy(data)
            return rows, -1, "embedded"
        except (OSError, json.JSONDecodeError):
            pass
    return [], -1, "missing"


def is_stale(age_seconds: int) -> bool:
    if age_seconds < 0:
        return True
    return age_seconds > STALE_AFTER_SECONDS


def fetch_aggregated(timeout: float = 30.0) -> dict:
    """Round-63: pull WPSecScan's nightly-aggregated multi-source feed.

    Returns a dict already in `wpsecscan/normalized-v1` format with
    a `_sources` field showing per-source contribution. Raises
    httpx.HTTPError on any network failure so the caller can fall back
    to direct-source fetches.

    Override the URL via WPSECSCAN_AGGREGATED_FEED_URL env var (e.g.
    if you run your own aggregator fork).
    """
    url = os.environ.get("WPSECSCAN_AGGREGATED_FEED_URL") or AGGREGATED_FEED_URL
    with httpx.Client(timeout=timeout, follow_redirects=True) as c:
        r = c.get(url, headers={"User-Agent": "WPSecScan/db-aggregated"})
        r.raise_for_status()
        data = r.json()
    if not isinstance(data, dict) or data.get("_format") != "wpsecscan/normalized-v1":
        raise RuntimeError(f"aggregated feed at {url} returned unexpected format")
    return data


def fetch_remote(timeout: float = 30.0) -> dict:
    last_exc: Exception | None = None
    with httpx.Client(timeout=timeout, follow_redirects=True) as c:
        for url in WORDFENCE_URLS:
            try:
                r = c.get(url, headers={"User-Agent": "WPSecScan/1.0 (db-update)"})
                if r.status_code == 410:
                    continue  # deprecated endpoint
                r.raise_for_status()
                return r.json()
            except httpx.HTTPError as e:
                last_exc = e
                continue
    if last_exc:
        raise last_exc
    raise RuntimeError("No Wordfence Intelligence endpoint reachable")


def save_cache(vulns: list[Vuln], sources: dict[str, int] | None = None) -> Path:
    """Round-63: optionally store per-source contribution counts so
    `wpsecscan db source-stats` can report breakdown."""
    cp = cache_path()
    if cp.is_symlink():
        cp.unlink()
    payload = {
        "_format": "wpsecscan/normalized-v1",
        "_fetched_at": int(time.time()),
        "_sources": sources or {},
        "vulns": [v.to_dict() for v in vulns],
    }
    cp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return cp


def fetch_osv_packagist(timeout: float = 60.0) -> list[Vuln]:
    """Fallback DB: pull WordPress plugin vulns from OSV.dev (Packagist ecosystem).
    OSV is free and unauthenticated."""
    out: list[Vuln] = []
    base = "https://api.osv.dev/v1/query"
    # We don't know all slugs up front; OSV doesn't expose a 'list all WP plugin
    # advisories' endpoint, so this is intentionally limited to a curated seed set.
    # The main use case for OSV here is per-scan lookup, but we still populate the
    # DB with the most-targeted plugins.
    seed_slugs = [
        "wpackagist-plugin/elementor", "wpackagist-plugin/woocommerce",
        "wpackagist-plugin/wordpress-seo", "wpackagist-plugin/all-in-one-seo-pack",
        "wpackagist-plugin/contact-form-7", "wpackagist-plugin/jetpack",
        "wpackagist-plugin/wp-statistics", "wpackagist-plugin/duplicator",
        "wpackagist-plugin/wpforms-lite", "wpackagist-plugin/wp-file-manager",
        "wpackagist-plugin/wp-super-cache", "wpackagist-plugin/litespeed-cache",
        "wpackagist-plugin/ultimate-member", "wpackagist-plugin/forminator",
        "wpackagist-plugin/essential-addons-for-elementor-lite",
        "wpackagist-plugin/wp-automatic", "wpackagist-plugin/bricks",
        "wpackagist-plugin/backup-backup", "wpackagist-plugin/learnpress",
        "wpackagist-plugin/wp-mail-smtp",
    ]
    with httpx.Client(timeout=timeout, follow_redirects=True) as c:
        for pkg in seed_slugs:
            try:
                r = c.post(base, json={"package": {"ecosystem": "Packagist", "name": pkg}})
                if r.status_code != 200:
                    continue
                slug = pkg.split("/", 1)[-1]
                for advisory in r.json().get("vulns", []) or []:
                    sev_score = None
                    sev_str = "medium"
                    for s in advisory.get("severity", []) or []:
                        if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                            try:
                                # Score may be embedded in vector string; pick the first numeric
                                sev_str_val = s.get("score", "")
                                import re as _re
                                m = _re.search(r"(\d+\.\d+)", sev_str_val)
                                if m:
                                    sev_score = float(m.group(1))
                            except Exception:
                                pass
                    if sev_score is not None:
                        sev_str = _cvss_to_severity(sev_score)
                    # Pull every (introduced, fixed) pair from OSV ranges and
                    # emit one Vuln per pair. Previously we kept overwriting
                    # `fixed` across loops, so multi-branch ranges (e.g.,
                    # 7.0..7.1.2 and 8.0..8.0.5 simultaneously) lost the
                    # higher branch and missed real CVE matches.
                    pairs: list[tuple[str, str]] = []
                    for af in advisory.get("affected", []) or []:
                        for rg in af.get("ranges", []) or []:
                            introduced = ""
                            for ev in rg.get("events", []) or []:
                                if "introduced" in ev:
                                    introduced = ev["introduced"] or ""
                                elif "fixed" in ev:
                                    pairs.append((introduced, ev["fixed"] or ""))
                                    introduced = ""
                            # Range with introduced but no fixed → still vulnerable
                            if introduced:
                                pairs.append((introduced, ""))
                    # Fallback for advisories with no events at all
                    if not pairs:
                        pairs = [("", "")]
                    cves = [a for a in advisory.get("aliases", []) or [] if a.startswith("CVE-")]
                    refs = [r.get("url", "") for r in (advisory.get("references", []) or []) if isinstance(r, dict)]
                    for introduced, fixed in pairs:
                        out.append(Vuln(
                            slug=slug, type="plugin",
                            title=advisory.get("summary") or advisory.get("id") or "OSV advisory",
                            severity=sev_str, cve=cves[0] if cves else advisory.get("id", ""),
                            cvss=sev_score, fixed_in=fixed,
                            affected_from=introduced, affected_to=fixed, to_inclusive=False,
                            references=refs, description=advisory.get("details", "")[:1000],
                        ))
            except httpx.HTTPError:
                continue
    return out


def fetch_patchstack(token: str, timeout: float = 20.0) -> list[Vuln]:
    """A6: Patchstack DB integration. Their public API returns ~3-4k WordPress
    plugin/theme CVEs that Wordfence sometimes misses (or gets later)."""
    if not token:
        return []
    out: list[Vuln] = []
    url = "https://api.patchstack.com/v3/vulnerabilities"
    try:
        with httpx.Client(timeout=timeout, headers={"Authorization": f"Bearer {token}",
                                                     "User-Agent": "WPSecScan/db"}) as c:
            r = c.get(url)
            if r.status_code != 200:
                return []
            data = r.json() or []
    except (httpx.HTTPError, ValueError):
        return []
    for entry in (data if isinstance(data, list) else data.get("results", []) or []):
        try:
            slug = (entry.get("slug") or entry.get("software_slug") or "").lower()
            if not slug:
                continue
            type_ = (entry.get("type") or "plugin").lower()
            if type_ not in ("plugin", "theme"):
                type_ = "plugin"
            fixed = entry.get("fixed_in") or entry.get("patched_in")
            title = entry.get("title") or entry.get("name") or "Patchstack-reported vulnerability"
            sev_raw = (entry.get("severity") or "medium").lower()
            sev = sev_raw if sev_raw in ("info", "low", "medium", "high", "critical") else "medium"
            out.append(Vuln(
                slug=slug, type=type_,
                cve=entry.get("cve") or "",
                cvss=entry.get("cvss") or None,
                title=title,
                description=entry.get("description") or "",
                fixed_in=fixed or "",
                affected_from=entry.get("affected_from") or "",
                affected_to=entry.get("affected_to") or "",
                to_inclusive=True,
                severity=sev,
                references=entry.get("references") or [],
            ))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def update_db(verbose: bool = True, patchstack_token: str = "") -> tuple[int, Path]:
    """Pull the latest vulnerability DB.

    Round-63 precedence (defence in depth — each layer only runs if all
    earlier layers came back empty):

      1. WPSecScan aggregated feed (8 sources merged + deduped)
      2. Wordfence Intelligence direct  (only if #1 was empty)
      3. Patchstack premium overlay     (additive; runs if token is set, even
                                          when aggregated feed succeeded —
                                          adds entries Patchstack has that
                                          the free sources don't)
      4. OSV.dev fallback              (only if #1 + #2 were both empty)
      5. Embedded data/plugin_cves.json (offline fallback at load_local())
    """
    merged: list[Vuln] = []
    sources_used: dict[str, int] = {}

    # 1. Aggregated feed first — covers Wordfence + 7 other sources in one call.
    if verbose:
        print("[db] fetching WPSecScan aggregated feed...", flush=True)
    try:
        agg = fetch_aggregated()
        for raw in agg.get("vulns", []) or []:
            try:
                # Map aggregator's flat dict → db.Vuln, with defaults for fields
                # the aggregator doesn't carry (affected_from/to, to_inclusive, description)
                kwargs = {k: v for k, v in raw.items()
                          if k in Vuln.__dataclass_fields__}
                kwargs.setdefault("cvss", None)
                kwargs.setdefault("fixed_in", "")
                kwargs.setdefault("affected_from", "")
                kwargs.setdefault("affected_to", "")
                kwargs.setdefault("to_inclusive", True)
                kwargs.setdefault("references", [])
                kwargs.setdefault("description", "")
                merged.append(Vuln(**kwargs))
            except (TypeError, ValueError):
                continue
        # Preserve the aggregator's per-source counts for `db source-stats`.
        sources_used = dict(agg.get("_sources") or {})
        if verbose:
            print(f"[db] aggregated feed: {len(merged):,} entries "
                  f"(from {len(sources_used)} sources, generated "
                  f"{agg.get('_generated_at', 'unknown')})", flush=True)
    except (httpx.HTTPError, RuntimeError, KeyError) as e:
        if verbose:
            print(f"[db] aggregated feed unavailable ({e}); "
                  f"falling back to direct sources.", flush=True)

    # 2. Wordfence direct — only if the aggregator was empty/unreachable.
    wf_ok = False
    if not merged:
        if verbose:
            print("[db] fetching Wordfence Intelligence...", flush=True)
        try:
            raw = fetch_remote()
            wf_vulns = normalize_wordfence(raw)
            merged.extend(wf_vulns)
            wf_ok = True
            sources_used["wordfence_direct"] = len(wf_vulns)
            if verbose:
                print(f"[db] Wordfence direct: {len(wf_vulns):,} entries", flush=True)
        except (httpx.HTTPError, RuntimeError) as e:
            if verbose:
                print(f"[db] Wordfence direct unavailable ({e}).", flush=True)

    # A6: Patchstack (opt-in via token)
    if patchstack_token:
        if verbose:
            print("[db] fetching Patchstack...", flush=True)
        ps = fetch_patchstack(patchstack_token)
        if verbose:
            print(f"[db] Patchstack: {len(ps)} entries", flush=True)
        # Dedupe by (type, slug, cve) — Patchstack often has the same CVE Wordfence does.
        seen = {(v.type, v.slug, v.cve) for v in merged if v.cve}
        added = 0
        for v in ps:
            if (v.type, v.slug, v.cve) not in seen:
                merged.append(v)
                added += 1
        if added:
            sources_used["patchstack_premium"] = added

    if merged:
        cp = save_cache(merged, sources=sources_used)
        if verbose:
            print(f"[db] cached {len(merged)} merged entries to {cp}", flush=True)
        return len(merged), cp

    # Fall through to OSV if everything else yielded nothing
    if not wf_ok:
        if verbose:
            print("[db] Falling back to OSV.dev...", flush=True)
        vulns = fetch_osv_packagist()
        if not vulns:
            raise RuntimeError(
                "Aggregated feed, Wordfence, Patchstack, and OSV.dev all "
                "returned no usable data. Embedded fallback DB will continue to be used."
            )
        sources_used["osv"] = len(vulns)
        cp = save_cache(vulns, sources=sources_used)
        if verbose:
            print(f"[db] cached {len(vulns)} OSV entries to {cp}", flush=True)
        return len(vulns), cp
    # Shouldn't reach here
    raise RuntimeError("DB update produced no entries.")


def _split_pre_release(v: str) -> tuple[str, str]:
    """Split `1.2.3-rc1` into ('1.2.3', 'rc1'). For `1.2.3`, returns ('1.2.3', '')."""
    for sep in ("-", "+", "_"):
        if sep in v:
            base, _, tag = v.partition(sep)
            return base, tag
    # Inline alpha tag with no separator (`1.2.3rc1`)
    for i, ch in enumerate(v):
        if ch.isalpha():
            return v[:i], v[i:]
    return v, ""


def ver_parts(v: str) -> list[int]:
    base, _tag = _split_pre_release(v)
    out: list[int] = []
    for p in base.split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        out.append(int(num) if num else 0)
    return out


def ver_lt(a: str, b: str) -> bool:
    pa, pb = ver_parts(a), ver_parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    if pa != pb:
        return pa < pb
    # Numeric segments equal: pre-release tag of `a` makes it less than tag-less `b`.
    # `1.2.3-rc1` < `1.2.3`, `1.2.3` == `1.2.3`, `1.2.3-rc1` < `1.2.3-rc2`.
    ta = _split_pre_release(a)[1]
    tb = _split_pre_release(b)[1]
    if ta == tb:
        return False
    if ta and not tb:
        return True   # pre-release < release
    if tb and not ta:
        return False  # release > pre-release
    return ta < tb    # both have tags, compare lexicographically


def ver_lte(a: str, b: str) -> bool:
    return a == b or ver_lt(a, b)


def affected(installed: str, vuln: Vuln) -> bool:
    """Is `installed` in the vulnerable range of `vuln`?"""
    if not installed:
        return False
    if vuln.affected_from and ver_lt(installed, vuln.affected_from):
        return False
    if vuln.affected_to:
        if vuln.to_inclusive:
            if ver_lt(vuln.affected_to, installed):
                return False
        else:
            if ver_lte(vuln.affected_to, installed):
                return False
    elif vuln.fixed_in:
        # Without affected_to, fall back to fixed_in: vulnerable iff installed < fixed_in
        return ver_lt(installed, vuln.fixed_in)
    return True


def find_for(vulns: Iterable[Vuln], type_: str, slug: str, installed_version: str | None) -> list[Vuln]:
    """Return vulns affecting `installed_version`. If version is unknown, return
    an empty list — callers should surface a low-confidence "version unknown"
    finding instead of dumping every historical CVE for the slug. Previously
    this returned all vulns when version was None, producing dozens of stale
    findings on plugins with rich CVE histories."""
    out: list[Vuln] = []
    slug = (slug or "").lower()
    if not installed_version:
        return out
    for v in vulns:
        if v.type != type_ or v.slug != slug:
            continue
        if affected(installed_version, v):
            out.append(v)
    return out


def has_any_for(vulns: Iterable[Vuln], type_: str, slug: str) -> bool:
    """Whether the DB contains ANY vulns for the slug, regardless of version.
    Used by callers to surface a low-confidence "version not detected" finding."""
    slug = (slug or "").lower()
    return any(v.type == type_ and v.slug == slug for v in vulns)


# ============================================================
# Round-61 — auto-update extras (status, subscribe, signatures)
# ============================================================

def cached_sources() -> dict[str, int]:
    """Round-63: read the `_sources` per-source contribution dict from
    the local cache. Returns empty dict if cache doesn't have it (cache
    written by an old version, or by Wordfence-direct without aggregation)."""
    cp = cache_path()
    if not cp.exists() or cp.is_symlink():
        return {}
    try:
        data = json.loads(cp.read_text(encoding="utf-8"))
        s = data.get("_sources") or {}
        return s if isinstance(s, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def status() -> dict:
    """Snapshot of the local vuln-DB state, for `wpsecscan db status`."""
    vulns, age, source = load_local()
    cp = cache_path()
    return {
        "source":       source,
        "entry_count":  len(vulns),
        "age_seconds":  age,
        "stale":        is_stale(age) if age >= 0 else True,
        "cache_path":   str(cp),
        "cache_exists": cp.exists(),
        "stale_after_seconds": STALE_AFTER_SECONDS,
        "next_refresh_due_seconds": max(0, STALE_AFTER_SECONDS - max(0, age)) if age >= 0 else 0,
    }


def _subscriptions_path() -> Path:
    return cache_dir() / "cve_subscriptions.json"


def subscriptions_load() -> list[dict]:
    p = _subscriptions_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or []
        return d if isinstance(d, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _subscriptions_save(subs: list[dict]) -> None:
    p = _subscriptions_path()
    try:
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(subs, indent=2), encoding="utf-8")
    except OSError:
        pass


def subscribe(webhook_url: str, *, site_url: str = "", label: str = "") -> dict:
    """Register a webhook to be fired by `watchers.cve_alert_check()` when
    a new CVE matches a tracked plugin/theme. Returns the new entry.

    `site_url` is optional — if set, only fire for that site; else fire for all.
    """
    if not webhook_url or not webhook_url.startswith(("http://", "https://")):
        raise ValueError("webhook_url must be http(s)://")
    subs = subscriptions_load()
    entry = {
        "webhook_url": webhook_url,
        "site_url":    site_url or "*",
        "label":       label or "default",
        "added_at":    int(time.time()),
    }
    # Dedupe by (webhook_url, site_url)
    subs = [s for s in subs if not (s.get("webhook_url") == webhook_url
                                       and s.get("site_url") == entry["site_url"])]
    subs.append(entry)
    _subscriptions_save(subs)
    return entry


def unsubscribe(webhook_url: str, *, site_url: str = "") -> bool:
    """Remove a subscription. Returns True if anything was removed."""
    subs = subscriptions_load()
    target_site = site_url or "*"
    new = [s for s in subs if not (s.get("webhook_url") == webhook_url
                                      and s.get("site_url") == target_site)]
    if len(new) == len(subs):
        return False
    _subscriptions_save(new)
    return True


# --- Exploit-signature refresh (overrides bundled data/exploit_signatures.json) ---

EXPLOIT_SIGS_REMOTE_URL = (
    "https://raw.githubusercontent.com/bryanflowers/wpsecscan/"
    "main/wpsecscan/data/exploit_signatures.json"
)


def exploit_signatures_cache_path() -> Path:
    return cache_dir() / "exploit_signatures.json"


def refresh_exploit_signatures(timeout: float = 20.0) -> dict:
    """Pull the latest exploit-signatures JSON from GitHub raw. On success,
    cache to ~/.wpsecscan/exploit_signatures.json so users get updates
    without reinstalling the binary.

    Returns {ok: bool, bytes: int, path: str, error?: str}.
    """
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return {"ok": False, "error": "WPSECSCAN_NO_NETWORK set"}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as c:
            r = c.get(EXPLOIT_SIGS_REMOTE_URL)
            if r.status_code != 200 or not r.content:
                return {"ok": False, "error": f"HTTP {r.status_code}"}
            # Validate it parses as JSON before overwriting cache
            try:
                json.loads(r.text)
            except json.JSONDecodeError as e:
                return {"ok": False, "error": f"bad JSON: {e}"}
            p = exploit_signatures_cache_path()
            if p.is_symlink():
                p.unlink()
            p.write_bytes(r.content)
            return {"ok": True, "bytes": len(r.content), "path": str(p)}
    except (httpx.HTTPError, OSError) as e:
        return {"ok": False, "error": str(e)}


def load_exploit_signatures() -> dict:
    """Prefer the cached refresh over the bundled file.

    Skips symlinked cache files (defence-in-depth — refuses to follow
    attacker-planted symlinks under ~/.wpsecscan/).
    """
    cache = exploit_signatures_cache_path()
    for p in (cache, Path(__file__).resolve().parent / "data" / "exploit_signatures.json"):
        if not p.exists():
            continue
        if p.is_symlink():
            continue
        try:
            return json.loads(p.read_text(encoding="utf-8")) or {}
        except (OSError, json.JSONDecodeError):
            continue
    return {}
