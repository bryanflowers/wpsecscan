"""Subdomain discovery via certificate transparency (crt.sh).

For each discovered subdomain, do a quick DNS resolve + HTTP probe to flag:
  - Subdomains pointing to dangling CDN providers (takeover candidates)
  - Subdomains exposing dev/staging/admin panels
"""
from __future__ import annotations

import asyncio
import re
import socket
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding

# FEAT-025: for each takeover-candidate vendor, point the operator at the
# exact registrar/signup URL so they can verify whether the resource is
# still claimable before treating the finding as a false-positive.
TAKEOVER_REGISTRAR_URL = {
    "github.io":          "https://pages.github.com/  (claim via repo `<user>/<repo>.github.io`)",
    "herokuapp.com":      "https://dashboard.heroku.com/new-app  (app name = the dangling subdomain prefix)",
    "herokudns.com":      "https://dashboard.heroku.com/new-app",
    "azurewebsites.net":  "https://portal.azure.com/  (create App Service with the dangling name)",
    "cloudapp.net":       "https://portal.azure.com/  (Cloud Service classic)",
    "s3.amazonaws.com":   "https://s3.console.aws.amazon.com/  (create bucket with the exact name)",
    "trafficmanager.net": "https://portal.azure.com/  (Traffic Manager Profile)",
    "readme.io":          "https://readme.io/  (claim the project)",
    "zendesk.com":        "https://www.zendesk.com/register/  (re-create the help center)",
    "surge.sh":           "`surge` CLI: `surge ./public your-name.surge.sh`",
    "fastly.net":         "https://manage.fastly.com/  (Fastly service)",
    "netlify.app":        "https://app.netlify.com/  (create site with that subdomain)",
    "ghost.io":           "https://ghost.org/  (create publication with that name)",
    "intercom.help":      "https://app.intercom.com/  (Help Center workspace)",
    "strikingly.com":     "https://www.strikingly.com/s/sign_up",
    "tumblr.com":         "https://www.tumblr.com/register  (claim the username)",
    "uservoice.com":      "https://www.uservoice.com/sign-up/",
    "wpengine.com":       "https://my.wpengine.com/  (rare — install must be on a free subdomain)",
    "shopify.com":        "https://www.shopify.com/  (create store with that myshopify subdomain)",
    "squarespace.com":    "https://www.squarespace.com/  (create site)",
    "statuspage.io":      "https://manage.statuspage.io/  (claim subdomain in StatusPage account)",
    "teamwork.com":       "https://www.teamwork.com/sign-up",
    "unbouncepages.com":  "https://app.unbounce.com/  (page builder, custom domain step)",
    "wishpond.com":       "https://app.wishpond.com/",
    "kinsta.com":         "https://my.kinsta.com/  (rare — claimable on temporary domains)",
    "agilecrm.com":       "https://www.agilecrm.com/  (create help center)",
    "smartling.com":      "https://dashboard.smartling.com/",
    "anima.io":           "https://www.animaapp.com/  (publish site)",
}


def _takeover_registrar_hint(host: str) -> str | None:
    """Return a registrar URL hint for a takeover-candidate vendor host, or None."""
    for vendor, url in TAKEOVER_REGISTRAR_URL.items():
        if vendor in host:
            return url
    return None


# Vendor fingerprint -> takeover-prone if CNAME points there but no resource exists.
# Source: github.com/EdOverflow/can-i-take-over-xyz + manual additions.
DANGLING_CNAME_FINGERPRINTS = (
    ("github.io",         "There isn't a GitHub Pages site here"),
    ("github.io",         "For root URLs (like http://example.com/) you must provide an index.html"),
    ("herokuapp.com",     "No such app"),
    ("herokudns.com",     "No such app"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudapp.net",      "404 Not Found"),
    ("s3.amazonaws.com",  "NoSuchBucket"),
    ("s3.amazonaws.com",  "The specified bucket does not exist"),
    ("trafficmanager.net","404 Web Site not found"),
    ("readme.io",         "Project doesnt exist"),
    ("zendesk.com",       "Help Center Closed"),
    ("surge.sh",          "project not found"),
    ("fastly.net",        "Fastly error: unknown domain"),
    ("netlify.app",       "Not Found - Request ID"),
    ("netlify.com",       "Not Found - Request ID"),
    # A4 round-S extensions:
    ("ghost.io",          "Domain not configured"),
    ("intercom.help",     "This page is reserved for artistic dogs"),
    ("strikingly.com",    "PAGE NOT FOUND"),
    ("tumblr.com",        "Whatever you were looking for doesn't currently exist"),
    ("uservoice.com",     "This UserVoice subdomain is currently available!"),
    ("wpengine.com",      "The site you were looking for couldn't be found"),
    ("shopify.com",       "Sorry, this shop is currently unavailable"),
    ("squarespace.com",   "No Such Account"),
    ("statuspage.io",     "You are being redirected"),
    ("teamwork.com",      "Oops - We didn't find your site"),
    ("unbouncepages.com", "The requested URL was not found on this server"),
    ("wishpond.com",      "https://www.wishpond.com/404?campaign=true"),
    ("kinsta.com",        "No Site For Domain"),
    ("agilecrm.com",      "Sorry, this page is no longer available"),
    ("smartling.com",     "Domain is not configured"),
    ("anima.io",          "If this is your website and you've just created it"),
    ("vend.com",          "Looks like you've traveled too far into cyberspace"),
    ("getresponse.com",   "Page not found"),
    ("acquia-test.co",    "The site you are looking for could not be found"),
)

SUSPICIOUS_LABELS = ("dev.", "staging.", "stage.", "test.", "qa.", "uat.", "demo.", "admin.", "internal.", "vpn.", "backup.", "old.", "preview.")


async def _crt_sh(domain: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            r.raise_for_status()
            data = r.json()
        out = set()
        for row in data or []:
            name = row.get("name_value") or ""
            for n in name.replace("\\n", "\n").splitlines():
                n = n.strip().lower()
                if not n or n.startswith("*"):
                    continue
                if n.endswith(domain.lower()):
                    out.add(n)
        return sorted(out)
    except (httpx.HTTPError, ValueError, KeyError):
        return []


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    parsed = urlparse(ctx["target"])
    host = parsed.hostname or ""
    if not host or host.count(".") < 1:
        findings.append(
            Finding(
                severity="info",
                title="Subdomain discovery skipped (target is an IP or localhost)",
                evidence=f"target host: {host}",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # Take the apex (last two labels) for the crt.sh query
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host

    step(f"querying crt.sh for *.{apex}...")
    subs = await _crt_sh(apex)
    if not subs:
        findings.append(
            Finding(
                severity="info",
                title=f"No subdomains found via certificate transparency for {apex}",
                evidence="crt.sh returned no records (or the query failed).",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    suspicious = [s for s in subs if any(lab in s for lab in SUSPICIOUS_LABELS)]
    if suspicious:
        findings.append(
            Finding(
                severity="low",
                title=f"{len(suspicious)} subdomain(s) with sensitive labels",
                evidence="\n".join(f"  - {s}" for s in suspicious[:25]),
                remediation=(
                    "Audit each — staging/dev/admin panels should be behind a VPN or IP allow-list, not "
                    "publicly indexable. Certificate transparency makes them effectively public."
                ),
                url=ctx["target"],
            )
        )

    # Probe up to 25 random subdomains for takeover candidates.
    # Use asyncio.to_thread for the sync DNS resolve so we don't block the loop.
    step("probing first 25 subdomains for takeover indicators...")
    takeover_candidates: list[tuple[str, str]] = []

    async def _probe(sub: str, probe_client: httpx.AsyncClient) -> tuple[str, str] | None:
        ip = await asyncio.to_thread(_resolve, sub)
        if not ip:
            return None
        # A4: try BOTH https and http — some CDN providers (Heroku, Netlify) reject
        # https for unconfigured apps with a TLS handshake failure, so the marker
        # only appears over plain HTTP.
        # B15 (v2.8.0) — resolve the CNAME chain so we can validate
        # both halves of the (cname_fragment, body_marker) tuple in
        # DANGLING_CNAME_FINGERPRINTS. Pre-fix code unpacked
        # `_cname_frag` but never used it, so a subdomain serving the
        # Heroku "no such app" page because some Heroku app happened
        # to mirror that text was wrongly flagged as a GitHub Pages
        # takeover. Now we require BOTH the CNAME to point at the
        # matching provider AND the body to contain the marker.
        cname_chain = ""
        try:
            import socket as _sock
            cname_chain = (_sock.getfqdn(sub) or "").lower()
        except (OSError, UnicodeError):
            pass
        for scheme in ("https", "http"):
            try:
                r = await probe_client.get(f"{scheme}://{sub}/", headers={"Host": sub})
            except httpx.HTTPError:
                continue
            body = (r.text or "")[:4000]
            for cname_frag, marker in DANGLING_CNAME_FINGERPRINTS:
                # Body marker is necessary. CNAME-fragment is supportive
                # when we successfully resolved one; if resolution
                # failed we fall back to body-only match (preserving
                # the pre-fix recall for hosts where getfqdn returns
                # the original name).
                if marker.lower() not in body.lower():
                    continue
                if cname_chain and cname_frag.lower() not in cname_chain:
                    continue
                return sub, marker
        return None

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as probe_client:
        # Parallel probes — bounded to 25 by the slice. asyncio.gather lets the
        # event loop overlap DNS + HTTP across hosts instead of serializing.
        probes = [_probe(sub, probe_client) for sub in subs[:25]]
        # v2.8.5 M6 — pre-fix return_exceptions=False propagated the
        # first failed probe and dropped all 24 partial results; one
        # transient DNS error killed the whole takeover sweep. Now
        # exceptions become per-probe `None`s and we filter them out.
        results = await asyncio.gather(*probes, return_exceptions=True)
        takeover_candidates = [
            r for r in results
            if r is not None and not isinstance(r, BaseException)
        ]

    # B7: cookie-tossing chain — if the main site sets cookies on `.target.com`
    # (apex domain) AND we have a takeover candidate, an attacker can register
    # the dangling resource, set a cookie on `.target.com` from the takeover
    # subdomain, and that cookie will be sent by the victim's browser on the
    # main site too — full session hijack class.
    apex_cookie_set = False
    try:
        main_r = await client.get("/")
        if main_r is not None and hasattr(main_r.headers, "get_list"):
            apex_lc = apex.lower()
            # Match `Domain=apex` or `Domain=.apex` followed by ; / whitespace / end-of-string.
            # Plain substring matching false-positives on lookalikes like `Domain=myexample.com`.
            cookie_domain_re = re.compile(
                rf"domain=\.?{re.escape(apex_lc)}(?:\s*[;,]|\s*$)",
                re.IGNORECASE,
            )
            for sc in main_r.headers.get_list("set-cookie"):
                if cookie_domain_re.search(sc):
                    apex_cookie_set = True
                    break
    except Exception:  # noqa: BLE001
        pass

    if takeover_candidates and apex_cookie_set:
        findings.append(
            Finding(
                severity="critical",
                title="COOKIE-TOSSING CHAIN: takeover-able subdomain + apex-scoped cookies",
                evidence=(
                    f"Takeover candidates: {', '.join(s for s, _m in takeover_candidates[:5])}\n"
                    f"Main site sets cookies on `.{apex}` (apex scope).\n\n"
                    "An attacker who claims the dangling SaaS resource can set cookies on `.{apex}` "
                    "from that subdomain. The victim's browser will then SEND that attacker-controlled "
                    "cookie to the MAIN site on the next visit — session-fixation / session-hijack."
                ),
                remediation=(
                    "1. Fix the takeover candidate FIRST (reclaim the SaaS resource or delete the DNS record).\n"
                    "2. Restrict the main site's session cookies to the HOST scope only (omit the Domain= "
                    "attribute, or set it to the exact apex without leading dot)."
                ),
                url=ctx["target"],
            )
        )

    if takeover_candidates:
        # A4: actively-confirmed (the provider's "unclaimed" marker was in the
        # response body) — escalate to critical. The attacker can register the
        # resource on that provider and serve content from YOUR subdomain.
        # Annotate each candidate with the vendor's registrar URL so the
        # operator can verify whether the resource is still claimable from
        # the exact signup page (FEAT-025).
        ev_lines = []
        for s, m in takeover_candidates:
            line = f"  - {s}: matched signature '{m[:60]}'"
            hint = _takeover_registrar_hint(s)
            if hint:
                line += f"\n      verify here: {hint}"
            ev_lines.append(line)
        findings.append(
            Finding(
                severity="critical",
                title=f"{len(takeover_candidates)} CONFIRMED subdomain takeover candidate(s)",
                evidence="\n".join(ev_lines),
                remediation=(
                    "These subdomains have DNS records pointing to a CDN/SaaS provider that returns an "
                    "'unclaimed/missing' page — meaning anyone can register the resource on that provider "
                    "and serve content from YOUR subdomain. Either:\n"
                    "  1. Reclaim the resource on the SaaS provider (recreate the GitHub Pages repo, "
                    "the Heroku app, the S3 bucket, etc.) — see the per-vendor registrar URLs in the "
                    "evidence above.\n"
                    "  2. Remove the dangling DNS record (CNAME / A) immediately.\n\n"
                    "Real-world impact: cookie hijacking (subdomain cookies leak), phishing under your "
                    "brand, malware distribution from your domain, email DMARC bypass."
                ),
                url=ctx["target"],
            )
        )

    findings.append(
        Finding(
            severity="info",
            title=f"{len(subs)} subdomain(s) discovered via crt.sh for {apex}",
            evidence="First 10: \n" + "\n".join(f"  - {s}" for s in subs[:10]),
            remediation="No action needed unless you didn't intend these subdomains to be public.",
            url=f"https://crt.sh/?q=%25.{apex}",
        )
    )

    return findings
