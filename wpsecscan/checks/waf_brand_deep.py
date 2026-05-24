"""Round-62 #B23 — WAF brand fingerprinting (deep — beyond round-Q's `waf`).

Adds detection for Imperva (Incapsula), F5 BIG-IP / ASM, Barracuda, NSFOCUS,
ModSecurity CRS version sniff, Citrix NetScaler, FortiWeb, Radware AppWall.
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


# Each tuple: (vendor, [header-regexes], [body-substrings], [cookie-substrings])
FINGERPRINTS = [
    ("Imperva (Incapsula)",
        [re.compile(r"x-iinfo:", re.IGNORECASE),
          re.compile(r"x-cdn:\s*Incapsula", re.IGNORECASE)],
        ["Incapsula incident ID", "_Incapsula_Resource"],
        ["visid_incap_", "incap_ses_"]),
    ("F5 BIG-IP / ASM",
        [re.compile(r"x-wa-info:", re.IGNORECASE),
          re.compile(r"server:\s*BIG-IP", re.IGNORECASE),
          re.compile(r"x-bigipreqid:", re.IGNORECASE)],
        ["The requested URL was rejected. Please consult with your administrator."],
        ["BIGipServer", "TS01", "F5_ST"]),
    ("Barracuda WAF",
        [re.compile(r"server:\s*Barracuda", re.IGNORECASE)],
        ["Barracuda Networks", "barra_counter_session"],
        ["barra_counter_session"]),
    ("Citrix NetScaler",
        [re.compile(r"^cneonction:", re.IGNORECASE),  # NetScaler typo: "cneonction" (sic)
          re.compile(r"^nnCoection:", re.IGNORECASE),
          re.compile(r"via:.*NS-CACHE", re.IGNORECASE)],
        [], ["NSC_"]),
    ("FortiWeb (Fortinet)",
        [re.compile(r"server:\s*FortiWeb", re.IGNORECASE),
          re.compile(r"x-fw-ip:", re.IGNORECASE)],
        ["FortiGate", "FortiWeb", "FORTINET"],
        ["FORTIWAFSID"]),
    ("Radware AppWall",
        [re.compile(r"x-sl-compstate:", re.IGNORECASE)],
        ["AppWall"], []),
    ("NSFOCUS WAF",
        [re.compile(r"server:\s*NSFocus", re.IGNORECASE),
          re.compile(r"x-powered-by-360wzb:", re.IGNORECASE)],
        ["NSFOCUS"], []),
    ("ModSecurity CRS",
        [re.compile(r"server:.*mod_security", re.IGNORECASE),
          re.compile(r"x-modsecurity:", re.IGNORECASE)],
        ["Mod_Security", "blocked by mod_security", "modsecurity"], []),
    ("AWS WAF",
        [re.compile(r"x-amzn-requestid:", re.IGNORECASE),
          re.compile(r"x-amzn-errortype:.*WAF", re.IGNORECASE)],
        ["AWSALB", "aws-waf"], ["aws-waf-token"]),
    ("Azure Front Door",
        [re.compile(r"x-azure-ref:", re.IGNORECASE),
          re.compile(r"x-cache:.*Front-Door", re.IGNORECASE)],
        [], []),
    ("Google Cloud Armor",
        [re.compile(r"server:.*Cloud Armor", re.IGNORECASE)],
        ["Google Cloud Armor"], ["GCLB"]),
]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("WAF brand probe: GET /...")
    r = await client.get("/")
    if r is None:
        return [Finding(severity="info", title="WAF brand audit — no response",
                        evidence="", remediation="No action.", url=ctx["target"])]
    headers_blob = "\n".join(f"{k}: {v}" for k, v in (r.headers or {}).items())
    body = (r.text or "")[:50_000]
    cookies = (r.headers or {}).get("Set-Cookie", "")

    detected: list[str] = []
    for vendor, header_pats, body_subs, cookie_subs in FINGERPRINTS:
        matched = False
        for pat in header_pats:
            if pat.search(headers_blob):
                matched = True
                break
        if not matched:
            for sub in body_subs:
                if sub.lower() in body.lower():
                    matched = True
                    break
        if not matched:
            for sub in cookie_subs:
                if sub.lower() in cookies.lower():
                    matched = True
                    break
        if matched:
            detected.append(vendor)
            # Cross-reference with the existing `waf` ctx shared so downstream
            # aggressive checks can throttle their probes
            ctx.setdefault("shared", {}).setdefault("waf_brands", []).append(vendor)

    if not detected:
        return [Finding(severity="info", title="WAF brand audit — no commercial WAF detected",
                        evidence=f"Probed {len(FINGERPRINTS)} vendors.",
                        remediation="No action.", url=ctx["target"])]

    return [Finding(
        severity="info",
        title=f"WAF detected: {', '.join(detected)}",
        evidence=f"Detected via headers/body/cookies: {', '.join(detected)}",
        remediation=("Confirm the WAF is in BLOCK mode (not just detect/log). "
                      "Aggressive scanner checks may be silently dropped — "
                      "consider whitelisting the scanner source IP via `wpsecscan/waf_tuning.py`."),
        url=ctx["target"],
    )]
