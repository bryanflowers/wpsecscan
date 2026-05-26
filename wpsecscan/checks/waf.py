"""WAF / CDN detection.

Runs early. Stashes the detected WAF (if any) in ctx['shared']['waf'] so
aggressive checks downstream can interpret their results correctly.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# (fingerprint key, header name pattern (lower), value substring (lower), label)
HEADER_SIGNS = [
    ("server",           "cloudflare",                              "Cloudflare"),
    ("cf-ray",           "",                                        "Cloudflare"),
    ("cf-cache-status",  "",                                        "Cloudflare"),
    ("x-sucuri-id",      "",                                        "Sucuri"),
    ("x-sucuri-cache",   "",                                        "Sucuri"),
    ("x-wf-",            "",                                        "Wordfence"),
    ("x-wordfence-",     "",                                        "Wordfence"),
    ("server",           "wordfence",                               "Wordfence"),
    ("server",           "nginx-wallarm",                           "Wallarm"),
    ("x-akamai-",        "",                                        "Akamai"),
    ("server",           "akamaighost",                             "Akamai"),
    ("x-cdn",            "fastly",                                  "Fastly"),
    ("fastly-debug-state","",                                       "Fastly"),
    ("x-served-by",      "cache",                                   "Varnish/CDN"),
    ("server",           "barracuda",                               "Barracuda"),
    ("x-mod-pagespeed",  "",                                        "Google PageSpeed"),
    ("server",           "litespeed",                               "LiteSpeed"),
    ("x-litespeed",      "",                                        "LiteSpeed"),
    ("x-bitninja-",      "",                                        "BitNinja"),
    ("x-iinfo",          "",                                        "Imperva (Incapsula)"),
    ("x-cdn",            "imperva",                                 "Imperva"),
    ("server",           "incapsula",                               "Imperva (Incapsula)"),
    ("x-distil-cs",      "",                                        "Imperva Distil"),
    ("server",           "openresty",                               "OpenResty"),
    # `X-Cache` alone is set by plain Nginx fastcgi-cache and many ordinary
    # reverse-proxy configs — not a WAF. Pair with a CDN-specific token to
    # avoid annotating every cached site with "WAF interference".
    ("x-cache",          "hit from cloudfront",                     "AWS CloudFront"),
    ("x-cache",          "fastly",                                  "Fastly"),
    ("x-cache",          "cf-",                                     "Cloudflare"),
    ("x-amz-cf-id",      "",                                        "AWS CloudFront"),
    ("x-azure-ref",      "",                                        "Azure Front Door"),
]

COOKIE_SIGNS = [
    ("__cfduid",        "Cloudflare (legacy)"),
    ("__cf_bm",         "Cloudflare Bot Management"),
    ("cf_clearance",    "Cloudflare challenge"),
    ("sucuri_cloudproxy_uuid", "Sucuri Firewall"),
    ("incap_ses_",      "Imperva (Incapsula)"),
    ("visid_incap_",    "Imperva (Incapsula)"),
    ("AWSALB",          "AWS Application Load Balancer"),
    ("BIGipServer",     "F5 BIG-IP"),
]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("probing for WAF/CDN fingerprints on /...")
    r = await client.get("/")
    detected: dict[str, str] = {}
    if r is not None:
        headers_lower = {k.lower(): str(v) for k, v in r.headers.items()}
        for hname, vsub, label in HEADER_SIGNS:
            if hname in headers_lower:
                v = headers_lower[hname]
                if not vsub or vsub in v.lower():
                    detected.setdefault(label, f"{hname}: {v}")
        # Cookies via set-cookie (may be multi-valued)
        sc = headers_lower.get("set-cookie", "")
        for cname, label in COOKIE_SIGNS:
            if cname.lower() in sc.lower():
                detected.setdefault(label, f"Set-Cookie contains '{cname}'")

    # Try an obviously bad request and see if it gets blocked by a WAF rule
    step("sending a benign WAF tripwire request...")
    tripwire = await client.get("/", params={"q": "<script>alert(1)</script>"})
    # Sucuri occasionally returns 200 with a JS-redirect challenge page rather
    # than 403. Detect that pattern explicitly before falling through to the
    # status-code-only block logic.
    if tripwire is not None and tripwire.status_code == 200 and tripwire.text:
        body200 = tripwire.text[:2000].lower()
        if "sucuri website firewall" in body200 or "sucuri/cloudproxy" in body200:
            detected.setdefault("Sucuri", "tripwire returned 200 with Sucuri block-page body")
    if tripwire is not None and tripwire.status_code in (403, 406, 419, 429, 503):
        # Heuristic: a clean install returns 200; mid-3xx if redirect.
        body = (tripwire.text or "")[:2000].lower()
        if "cloudflare" in body or "ray id" in body:
            detected.setdefault("Cloudflare", "tripwire blocked (HTML body contains 'cloudflare')")
        elif "sucuri" in body:
            detected.setdefault("Sucuri", "tripwire blocked (HTML body contains 'sucuri')")
        elif "wordfence" in body:
            detected.setdefault("Wordfence", "tripwire blocked (HTML body contains 'wordfence')")
        elif any(tok in body for tok in ("akamai", "incapsula", "imperva", "fastly",
                                          "wallarm", "barracuda", "modsecurity",
                                          "mod_security", "this request has been blocked",
                                          "your request was blocked", "naxsi")):
            # Generic WAF block-page indicators
            detected.setdefault("Unknown WAF", f"tripwire returned HTTP {tripwire.status_code} with WAF-style block page")
        # Otherwise: a non-WAF 4xx/5xx (e.g. Nginx deny rule, app-level rate-limit
        # page) — do NOT annotate as "Unknown WAF". That mis-classification
        # downgrades every aggressive finding on hardened-without-WAF sites.

    if detected:
        ctx["shared"]["waf"] = list(detected.keys())
        lines = "\n".join(f"  - {label}: {evidence}" for label, evidence in detected.items())
        findings.append(
            Finding(
                severity="info",
                title=f"WAF / CDN detected: {', '.join(detected.keys())}",
                evidence=(
                    f"Detected via header/cookie fingerprints:\n{lines}\n\n"
                    "Aggressive checks downstream may be intercepted by this layer — "
                    "false-negatives are possible (the WAF blocks our probes before they reach WordPress)."
                ),
                remediation=(
                    "No action needed unless this is a misconfiguration. If you want a true picture of "
                    "underlying app security, scan the origin directly (e.g. via /etc/hosts override to "
                    "the origin IP) or whitelist your scanner IP in the WAF."
                ),
                url=ctx["target"],
                extra={"waf": list(detected.keys())},
            )
        )
    else:
        ctx["shared"]["waf"] = []
        findings.append(
            Finding(
                severity="info",
                title="No WAF / CDN fingerprints detected",
                evidence="Headers, cookies, and a tripwire request did not match known WAF signatures.",
                remediation="If you expect a WAF in front of this site, verify it's actually serving traffic for this hostname.",
                url=ctx["target"],
            )
        )

    return findings
