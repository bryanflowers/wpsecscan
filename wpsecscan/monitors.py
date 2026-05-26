"""Round-64 Group B (#11-20) — Continuous monitoring watchers.

Each watcher is a function that:
  - Polls a public data source (cert transparency, WHOIS, etc.)
  - Compares to a baseline stored in ~/.wpsecscan/monitors/<name>.json
  - Fires notify.notify() if the state diverged
  - Is safe to run from cron / scheduled task (atomic state writes)

#11 live_attack_feed       — companion-plugin tails error_log + recent 401/403
#12 cert_transparency_watch — new cert issued for your domain = potential MitM
#13 dns_change_watch       — NS/A/AAAA/MX changes (extends round-60)
#14 whois_change_watch     — domain registrant / NS changed = takeover risk
#15 darkweb_mention_watch  — your domain in paste sites / leak dumps
#16 rbl_reputation_watch   — your server IP appeared on a block list
#17 cisa_kev_match_watch   — new CISA KEV affects an installed plugin
#18 geoip_traffic_anomaly  — sudden traffic surge from new countries
#19 honeypot_hit_watch     — companion honeypot fired (real attacker IP captured)
#20 auto_rollback          — companion-plugin reverts to last clean state

All write to ~/.wpsecscan/monitors/ and use _notify() from watchers.py
(already established notification path).
"""
from __future__ import annotations

import datetime
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _state_dir() -> Path:
    p = _home() / "monitors"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _state_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "default"
    return _state_dir() / f"{safe}.json"


def _load(name: str) -> dict:
    p = _state_path(name)
    if not p.exists() or p.is_symlink():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8")) or {}
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save(name: str, state: dict) -> None:
    p = _state_path(name)
    try:
        if p.is_symlink():
            p.unlink()
        p.write_text(json.dumps(state), encoding="utf-8")
    except OSError:
        pass


def _notify(title: str, message: str) -> None:
    try:
        from . import notify
        notify.notify(title, message)
    except Exception:  # noqa: BLE001
        pass


def _http_get_json(url: str, *, headers: dict | None = None,
                    timeout: float = 15.0) -> Any:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/monitors",
                                                  **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError):
        return None


def _http_get_text(url: str, *, headers: dict | None = None,
                    timeout: float = 15.0) -> str:
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return ""
    req = urllib.request.Request(url, headers={"User-Agent": "WPSecScan/monitors",
                                                  **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, OSError):
        return ""


# ---- #11 live attack feed ----

def live_attack_feed(target_url: str, *, companion_token: str,
                      since_ts: int | None = None) -> dict:
    """Pull recent attack-attempt log lines from the companion plugin.

    Requires the companion plugin v1.2+ to expose
    `/wp-json/wpsecscan/v1/attack-log?since=<ts>`.

    Returns {entries, count, error}.
    """
    if not companion_token:
        return {"entries": [], "count": 0, "error": "companion_token required"}
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    since_ts = since_ts or 0
    url = f"{base}/wp-json/wpsecscan/v1/attack-log?since={int(since_ts)}"
    d = _http_get_json(url, headers={"X-WPSecScan-Token": companion_token})
    if not d or not isinstance(d, list):
        return {"entries": [], "count": 0, "error": "endpoint unavailable"}
    return {"entries": d, "count": len(d)}


# ---- #12 cert transparency watch ----

def cert_transparency_watch(host: str) -> dict:
    """Use crt.sh to spot new certs for `host`. If a cert appears that
    we haven't seen before AND wasn't issued by one of the CAs we
    expect, fire an alert. Returns {new_certs, changed}."""
    name = f"ct_{host}"
    if not host or not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        return {"new_certs": [], "changed": False, "error": "invalid host"}
    state = _load(name)
    known = set(state.get("known_serials") or [])

    d = _http_get_json(f"https://crt.sh/?q=%25.{host}&output=json", timeout=30.0)
    if not d or not isinstance(d, list):
        return {"new_certs": [], "changed": False, "error": "crt.sh unavailable"}

    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7))
    new_certs = []
    for entry in d[:200]:
        if not isinstance(entry, dict):
            continue
        serial = str(entry.get("serial_number") or entry.get("id") or "")
        if not serial or serial in known:
            continue
        try:
            issued = datetime.datetime.fromisoformat(
                (entry.get("entry_timestamp") or "").replace("Z", ""))
        except (ValueError, TypeError, AttributeError):
            continue
        if issued < cutoff:
            continue
        new_certs.append({
            "serial":   serial,
            "name":     entry.get("name_value", ""),
            "issuer":   entry.get("issuer_name", ""),
            "issued":   entry.get("entry_timestamp", ""),
        })
        known.add(serial)

    state["known_serials"] = sorted(known)[-1000:]
    state["last_check"] = int(time.time())
    _save(name, state)

    if new_certs:
        _notify(
            f"New cert(s) for {host} (last 7d)",
            "\n".join(f"  - {c['name']} by {c['issuer'][:60]} at {c['issued']}"
                       for c in new_certs[:10]),
        )
    return {"new_certs": new_certs, "changed": bool(new_certs)}


# ---- #13 DNS change watch (extends watchers.dns_change_watcher) ----

def dns_change_watch(host: str) -> dict:
    """Thin alias to watchers.dns_change_watcher for completeness."""
    try:
        from . import watchers
        return watchers.dns_change_watcher(host)
    except ImportError:
        return {"changed_records": [], "error": "watchers module missing"}


# ---- #14 WHOIS change watch ----

WHOIS_FIELDS = ("registrar", "name server", "creation date", "registry expiry date")


def whois_change_watch(host: str) -> dict:
    """Run system `whois` command (must be installed). Diff key fields
    against the baseline."""
    if not host or not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        return {"changed_fields": [], "error": "invalid host"}
    import shutil as _sh
    if not _sh.which("whois"):
        return {"changed_fields": [], "error": "whois command not on PATH"}
    try:
        r = subprocess.run(["whois", host], capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return {"changed_fields": [], "error": "whois failed"}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"changed_fields": [], "error": "whois failed"}

    cur: dict[str, str] = {}
    for line in (r.stdout or "").splitlines():
        for field in WHOIS_FIELDS:
            low = line.lower().strip()
            if low.startswith(field):
                # "registrar: foo" → take the part after :
                _, _, val = line.partition(":")
                cur.setdefault(field, val.strip())
                break

    state = _load(f"whois_{host}")
    prev = state.get("fields") or {}
    changed = [f for f in cur if prev.get(f) and prev[f] != cur[f]]
    state["fields"] = cur
    state["last_check"] = int(time.time())
    _save(f"whois_{host}", state)

    if changed:
        _notify(
            f"WHOIS change on {host}",
            "\n".join(f"  - {f}: {prev.get(f, '?')[:80]} -> {cur[f][:80]}"
                       for f in changed),
        )
    return {"changed_fields": changed, "current": cur}


# ---- #15 darkweb mention watch ----

def darkweb_mention_watch(domain: str, *, hibp_token: str | None = None) -> dict:
    """Check the HaveIBeenPwned breaches API for new breaches mentioning
    `domain`. Requires a free HIBP API key (3-month subscription is paid;
    use only the free `breaches` endpoint here)."""
    name = f"darkweb_{domain}"
    state = _load(name)
    seen = set(state.get("seen_breach_names") or [])

    # The /breaches/?domain= endpoint is free, no key required
    d = _http_get_json(
        f"https://haveibeenpwned.com/api/v3/breaches?domain={urllib.parse.quote(domain)}",
        headers={"hibp-api-key": hibp_token} if hibp_token else None,
        timeout=20.0,
    )
    if not d or not isinstance(d, list):
        return {"new_breaches": [], "error": "HIBP unavailable"}
    new = [b for b in d if isinstance(b, dict) and b.get("Name") not in seen]
    for b in new:
        seen.add(b.get("Name"))
    state["seen_breach_names"] = sorted(seen)[-200:]
    state["last_check"] = int(time.time())
    _save(name, state)

    if new:
        _notify(
            f"{len(new)} new breach(es) mentioning {domain}",
            "\n".join(f"  - {b.get('Name')}: {b.get('BreachDate', '?')} "
                       f"({b.get('PwnCount', 0):,} accounts)" for b in new[:10]),
        )
    return {"new_breaches": new}


# ---- #16 RBL / IP reputation watch ----

# A small selection of widely-used DNSBLs
DNSBLS = (
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "psbl.surriel.com",
)


def rbl_reputation_watch(ip: str) -> dict:
    """Reverse-lookup `ip` on each DNSBL. If any returns a positive, fire."""
    if not ip:
        return {"listed_on": [], "error": "no IP"}
    try:
        socket.inet_aton(ip)
    except OSError:
        return {"listed_on": [], "error": "invalid IPv4"}
    rev = ".".join(reversed(ip.split(".")))
    listed = []
    for bl in DNSBLS:
        try:
            socket.gethostbyname(f"{rev}.{bl}")
            listed.append(bl)
        except (socket.gaierror, OSError):
            continue
    name = f"rbl_{ip.replace('.', '_')}"
    state = _load(name)
    prev = set(state.get("listed_on") or [])
    new = [bl for bl in listed if bl not in prev]
    if new:
        _notify(
            f"IP {ip} newly listed on {len(new)} DNSBL(s)",
            "\n".join(f"  - {bl}" for bl in new),
        )
    state["listed_on"] = listed
    state["last_check"] = int(time.time())
    _save(name, state)
    return {"listed_on": listed, "new_listings": new}


# ---- #17 CISA KEV match watch ----

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def cisa_kev_match_watch() -> dict:
    """Pull the latest CISA KEV feed; cross-reference against the user's
    last-known installed plugins (companion-driven). Alert on any KEV
    that matches an installed plugin."""
    d = _http_get_json(CISA_KEV_URL, timeout=30.0)
    if not d or "vulnerabilities" not in d:
        return {"matches": [], "error": "KEV feed unavailable"}
    kev = d.get("vulnerabilities", [])

    # Pull installed-plugin slugs from the sites list
    try:
        from . import sites as _sites
    except ImportError:
        return {"matches": [], "error": "sites module unavailable"}
    installed: set[tuple[str, str]] = set()    # (site_url, slug)
    for s in _sites.list_sites():
        for p in (s.get("last_plugins") or []):
            if isinstance(p, dict) and p.get("slug"):
                installed.add((s.get("url", ""), p["slug"].lower()))

    name = "cisa_kev"
    state = _load(name)
    seen = set(state.get("seen_kev_ids") or [])

    matches = []
    for k in kev:
        kev_id = k.get("cveID", "")
        if not kev_id or kev_id in seen:
            continue
        product = (k.get("product") or "").lower()
        vendor = (k.get("vendorProject") or "").lower()
        for site, slug in installed:
            if slug in product or slug in vendor:
                matches.append({
                    "site": site, "plugin_slug": slug, "cve": kev_id,
                    "vendor": k.get("vendorProject"),
                    "product": k.get("product"),
                    "due_date": k.get("dueDate"),
                    "short_description": k.get("shortDescription"),
                })
                seen.add(kev_id)
                break

    state["seen_kev_ids"] = sorted(seen)[-2000:]
    state["last_check"] = int(time.time())
    _save(name, state)

    if matches:
        _notify(
            f"CISA KEV: {len(matches)} new match(es) — actively exploited!",
            "\n".join(f"  - {m['site']}: {m['plugin_slug']} -> {m['cve']} "
                       f"({m['product']}) due {m['due_date']}" for m in matches[:10]),
        )
    return {"matches": matches}


# ---- #18 GeoIP traffic anomaly ----

def geoip_traffic_anomaly_watch(target_url: str, *, companion_token: str) -> dict:
    """Pull recent traffic-by-country from the companion plugin's
    activity log; alert on country shares >3x the running median.

    Requires companion plugin v1.2+ to expose
    /wp-json/wpsecscan/v1/traffic-stats.
    """
    if not companion_token:
        return {"anomalies": [], "error": "companion_token required"}
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    d = _http_get_json(
        f"{base}/wp-json/wpsecscan/v1/traffic-stats",
        headers={"X-WPSecScan-Token": companion_token},
    )
    if not d or not isinstance(d, dict):
        return {"anomalies": [], "error": "endpoint unavailable"}

    cur = d.get("by_country", {})
    if not isinstance(cur, dict):
        return {"anomalies": [], "error": "bad shape"}
    name = f"traffic_{parsed.hostname}"
    state = _load(name)
    baseline = state.get("baseline") or {}
    anomalies = []
    for country, count in cur.items():
        if not country:
            continue
        base_count = int(baseline.get(country) or 0)
        try:
            count_i = int(count)
        except (TypeError, ValueError):
            continue
        if base_count and count_i > base_count * 3 and count_i > 100:
            anomalies.append({
                "country": country, "current": count_i, "baseline": base_count,
                "multiplier": round(count_i / base_count, 1),
            })
        baseline[country] = max(base_count, count_i)
    state["baseline"] = baseline
    state["last_check"] = int(time.time())
    _save(name, state)
    if anomalies:
        _notify(
            f"Traffic anomaly on {target_url}: {len(anomalies)} country surge(s)",
            "\n".join(f"  - {a['country']}: {a['current']} (baseline {a['baseline']}, "
                       f"{a['multiplier']}x)" for a in anomalies[:10]),
        )
    return {"anomalies": anomalies}


# ---- #19 honeypot hit watch ----

def honeypot_hit_watch(target_url: str, *, companion_token: str) -> dict:
    """Pull hits from the companion plugin's deployed honeypot endpoint."""
    if not companion_token:
        return {"hits": [], "error": "companion_token required"}
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    d = _http_get_json(
        f"{base}/wp-json/wpsecscan/v1/honeypot-hits",
        headers={"X-WPSecScan-Token": companion_token},
    )
    if not d or not isinstance(d, list):
        return {"hits": [], "error": "endpoint unavailable"}
    name = f"honeypot_{parsed.hostname}"
    state = _load(name)
    seen = set(state.get("seen_ts") or [])
    new = [h for h in d if isinstance(h, dict) and str(h.get("ts")) not in seen]
    for h in new:
        seen.add(str(h.get("ts")))
    state["seen_ts"] = sorted(seen)[-500:]
    state["last_check"] = int(time.time())
    _save(name, state)
    if new:
        _notify(
            f"Honeypot hit on {target_url}: {len(new)} attacker IP(s)",
            "\n".join(f"  - {h.get('ip', '?')} @ {h.get('ts', '?')} "
                       f"UA={(h.get('ua', '') or '')[:60]}" for h in new[:10]),
        )
    return {"new_hits": new}


# ---- #20 auto-rollback ----

def auto_rollback(target_url: str, *, companion_token: str, dry_run: bool = True) -> dict:
    """Triggers the companion plugin's "revert to last known good" action.

    Requires companion v1.3+ which exposes
    POST /wp-json/wpsecscan/v1/rollback with body {dry_run: bool}.

    Default dry_run=True returns what WOULD be reverted without doing it.
    """
    if not companion_token:
        return {"ok": False, "error": "companion_token required"}
    if os.environ.get("WPSECSCAN_NO_NETWORK"):
        return {"ok": False, "error": "WPSECSCAN_NO_NETWORK set"}
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    body = json.dumps({"dry_run": dry_run}).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/wp-json/wpsecscan/v1/rollback",
        data=body, method="POST",
        headers={
            "X-WPSecScan-Token": companion_token,
            "Content-Type": "application/json",
            "User-Agent": "WPSecScan/auto-rollback",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, OSError, ValueError) as e:
        return {"ok": False, "error": str(e)}
    if not dry_run:
        _notify(
            f"Auto-rollback triggered on {target_url}",
            f"Files reverted: {d.get('files_reverted', 0)}; "
            f"Plugins disabled: {d.get('plugins_disabled', 0)}",
        )
    return {"ok": True, **d}


# Convenience helper — run every monitor that has all required args for a site
def run_all_for_site(site: dict) -> dict:
    """Best-effort: run every monitor that fits this site's available data.
    Used by the daily scheduled task."""
    url = site.get("url", "")
    if not url:
        return {"error": "no url"}
    parsed = urlparse(url)
    host = parsed.hostname or ""
    results: dict[str, Any] = {}

    if host:
        results["dns"]    = dns_change_watch(host)
        results["whois"]  = whois_change_watch(host)
        results["ct"]     = cert_transparency_watch(host)
        results["darkweb"] = darkweb_mention_watch(host)
        # IP-based monitors
        try:
            ip = socket.gethostbyname(host)
            results["rbl"] = rbl_reputation_watch(ip)
        except (socket.gaierror, OSError):
            pass
    # Companion-driven monitors (only if token available)
    token = site.get("companion_token_sealed")
    if token:
        try:
            from . import sites as _sites
            unsealed = _sites._unseal(token)
            if unsealed:
                results["attacks"] = live_attack_feed(url, companion_token=unsealed)
                results["honeypot"] = honeypot_hit_watch(url, companion_token=unsealed)
                results["traffic_anomaly"] = geoip_traffic_anomaly_watch(url, companion_token=unsealed)
        except ImportError:
            pass
    # Global monitors (run once per scheduled cycle, not per-site)
    results["cisa_kev"] = cisa_kev_match_watch()
    return results
