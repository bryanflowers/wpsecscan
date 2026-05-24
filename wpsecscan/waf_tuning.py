"""Round-59 #101-104 — Real-time WAF tuning helpers.

#101 WAF allow-list generator — given a scan that produced 0 findings,
     emit an allow-list rule covering the scanner's source IP + UA
     so future scans don't trigger the WAF.
#102 Cloudflare API export — wraps `POST /accounts/{id}/rulesets` with
     the generated rules.
#103 ModSecurity CRS export — same rules in ModSec SecRule syntax.
#104 WAF testing mode — flip the WAF into a `log-only` mode via the
     CDN API for the duration of the scan, then restore.

Cloud-API wrappers require CF_API_TOKEN env var. Without it they're
no-ops returning structured "needs token" dicts so callers can render
the missing-config message gracefully.
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.error import HTTPError, URLError


# ---- #101 Allow-list generator ----

def generate_allow_list(scanner_ip: str, user_agent: str = "WPSecScan",
                          notes: str = "") -> dict:
    """Pure: returns a normalised allow-list spec from scanner identity."""
    return {
        "name": "WPSecScan-allow",
        "match": {
            "ip": scanner_ip,
            "user_agent": user_agent,
        },
        "notes": notes or "Allow WPSecScan from this source IP. Created automatically.",
    }


# ---- #102 Cloudflare API export ----

def cloudflare_publish_rule(zone_id: str, allow_spec: dict,
                              cf_api_token: str | None = None) -> dict:
    """Publish the allow-list as a Cloudflare ruleset.

    Returns {ok: bool, status: int, body: str | dict, hint?: str}.
    Will not run if CF_API_TOKEN is missing — instead returns a hint dict.
    """
    token = cf_api_token or os.environ.get("CF_API_TOKEN")
    if not token:
        return {"ok": False, "hint": "Set CF_API_TOKEN env var with `zone.firewall_access_rules:edit`."}
    if not zone_id or not isinstance(allow_spec, dict):
        return {"ok": False, "hint": "zone_id and allow_spec required"}

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    body = json.dumps({
        "mode": "whitelist",
        "configuration": {"target": "ip", "value": allow_spec.get("match", {}).get("ip", "")},
        "notes": allow_spec.get("notes", ""),
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                  "Content-Type": "application/json",
                  "User-Agent": "WPSecScan/waf_tuning"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"ok": r.status < 300, "status": r.status,
                     "body": json.loads(r.read().decode("utf-8", errors="replace"))}
    except (HTTPError, URLError, OSError, ValueError) as e:
        return {"ok": False, "status": getattr(e, "code", 0), "body": str(e)}


# ---- #103 ModSecurity CRS export ----

def to_modsec_rule(allow_spec: dict, rule_id: int = 990001) -> str:
    """Convert the normalised allow-list spec to a ModSecurity SecRule
    block. Returns "" if spec is malformed."""
    ip = (allow_spec or {}).get("match", {}).get("ip")
    ua = (allow_spec or {}).get("match", {}).get("user_agent")
    if not ip:
        return ""
    # Sanity: rule_id 980000-999999 is the "local" range CRS leaves alone
    if rule_id < 980000 or rule_id > 999999:
        rule_id = 990001
    parts = [
        f"SecRule REMOTE_ADDR \"@ipMatch {ip}\" \\",
        f"    \"id:{rule_id},phase:1,nolog,allow,ctl:ruleEngine=Off\"",
    ]
    if ua:
        # Escape quotes/backslashes per ModSec parsing
        ua_safe = ua.replace("\\", "\\\\").replace("\"", "\\\"")
        parts.append(f"SecRule REQUEST_HEADERS:User-Agent \"@streq {ua_safe}\" \\")
        parts.append(f"    \"id:{rule_id + 1},phase:1,nolog,allow,ctl:ruleEngine=Off\"")
    return "\n".join(parts)


# ---- #104 WAF testing mode ----

def cloudflare_set_security_level(zone_id: str, level: str,
                                     cf_api_token: str | None = None) -> dict:
    """Flip CF zone-wide security level. `level` must be one of
    {"off", "essentially_off", "low", "medium", "high", "under_attack"}."""
    valid = {"off", "essentially_off", "low", "medium", "high", "under_attack"}
    if level not in valid:
        return {"ok": False, "hint": f"level must be one of {valid}"}
    token = cf_api_token or os.environ.get("CF_API_TOKEN")
    if not token:
        return {"ok": False, "hint": "Set CF_API_TOKEN env var."}
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level"
    body = json.dumps({"value": level}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="PATCH",
        headers={"Authorization": f"Bearer {token}",
                  "Content-Type": "application/json",
                  "User-Agent": "WPSecScan/waf_tuning"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"ok": r.status < 300, "status": r.status,
                     "body": json.loads(r.read().decode("utf-8", errors="replace"))}
    except (HTTPError, URLError, OSError, ValueError) as e:
        return {"ok": False, "status": getattr(e, "code", 0), "body": str(e)}
