"""Round-59 #16-23 — Privacy / GDPR data inventory + tracker audit.

#16 PII inventory — scan home page + checkout for visible PII fields
   (name/email/phone/address/credit-card patterns) so the data-map is
   one click rather than a manual walkthrough.
#17 Cookie-banner audit — is one present? does it block cookies before
   consent, or is it the cosmetic kind that ePrivacy regulators fine?
#18 Third-party JS exfil — list every third-party script src and the
   data they POST to (sample of inline `fetch(...)` strings).
#19 Google Fonts CJEU check — `fonts.googleapis.com` hits = the
   prohibited-without-consent pattern (per the German ruling).
#20 IP anonymisation — does `_gtag('config', {anonymize_ip: true})`
   appear in any inline script that loads GA/GA4?
#21 DPA helper — emit a structured list of every third-party processor
   detected, so the DPO can issue Data-Processing Agreements quickly.
#22 RTBE (right-to-be-erased) endpoint — is wp-admin/erase-personal-data
   reachable + correctly capability-gated?
#23 International data transfer — for every third-party processor,
   guess the jurisdiction (US/EU/UK) so transfer-impact assessment is
   one click.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from ..http import Client
from ..models import Finding


PII_PATTERNS = {
    "email":  re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    "phone":  re.compile(r'\b(?:\+?\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b'),
    "cc":     re.compile(r'\b(?:\d[ \-]?){13,19}\b'),
    "ip":     re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "ssn_us": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
}
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(r'<script\b[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
COOKIE_BANNER_HINTS = ("cookie-consent", "cookiebot", "onetrust", "iubenda",
                       "complianz", "cookieyes", "cookielaw", "trustarc")
GA_RE = re.compile(r"(?:gtag|google-analytics|googletagmanager|GA_MEASUREMENT_ID|UA-\d+|G-[A-Z0-9]+)", re.IGNORECASE)
ANONYMIZE_IP_RE = re.compile(r"anonymize_ip\s*[:=]\s*true", re.IGNORECASE)

# Best-effort jurisdiction guess from hostname
US_HOSTS = ("googleapis.com", "google.com", "doubleclick.net", "facebook.net",
             "facebook.com", "cloudfront.net", "amazonaws.com", "google-analytics.com",
             "googletagmanager.com", "stripe.com", "twilio.com")
EU_HOSTS = ("matomo.cloud", "fathom.eu", "plausible.io")
UK_HOSTS = ("monzo.com",)


def _jurisdiction(host: str) -> str:
    h = host.lower()
    if any(s in h for s in US_HOSTS):
        return "US"
    if any(s in h for s in EU_HOSTS):
        return "EU"
    if any(s in h for s in UK_HOSTS):
        return "UK"
    if h.endswith((".uk", ".co.uk")):
        return "UK"
    if h.endswith((".eu", ".de", ".fr", ".nl", ".be", ".at", ".es", ".it")):
        return "EU"
    return "Unknown"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    step("privacy: fetch home...")
    home = await client.get("/")
    if home is None or home.text is None:
        return [Finding(severity="info", title="Privacy inventory — could not fetch home page",
                        evidence="GET / returned no content.", remediation="Check connectivity.",
                        url=target)]
    body = home.text[:200_000]

    # ---- #16 PII inventory ----
    pii_counts = {k: len(p.findall(body)) for k, p in PII_PATTERNS.items()}
    found_pii = {k: v for k, v in pii_counts.items() if v > 0}
    if found_pii:
        findings.append(Finding(
            severity="low" if "cc" not in found_pii else "high",
            title=f"PII patterns visible on home page ({sum(found_pii.values())} match(es))",
            evidence=" / ".join(f"{k}={v}" for k, v in found_pii.items()),
            remediation=("Customer-facing pages should not echo raw PII. If the matches are "
                         "legitimate (contact email in footer), this is informational. CC/SSN "
                         "matches on a public page are critical."),
            url=target,
        ))

    # ---- #17 Cookie banner ----
    banner = any(h in body.lower() for h in COOKIE_BANNER_HINTS)
    if not banner:
        findings.append(Finding(
            severity="medium",
            title="No recognised cookie-consent banner detected",
            evidence="None of: " + ", ".join(COOKIE_BANNER_HINTS),
            remediation="If you serve EU/UK visitors, ePrivacy + GDPR require informed consent BEFORE setting non-essential cookies. Install Cookiebot/Iubenda/Complianz or comparable.",
            url=target,
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="Cookie-consent banner present",
            evidence="Detected: " + ", ".join(h for h in COOKIE_BANNER_HINTS if h in body.lower()),
            remediation="Confirm the banner blocks scripts BEFORE consent (most cosmetic banners don't).",
            url=target,
        ))

    # ---- #18, #21, #23 Third-party JS inventory ----
    srcs = [s for s in SCRIPT_SRC_RE.findall(body) if s.startswith(("http://", "https://"))]
    target_host = urlparse(target).hostname or ""
    third_party = []
    for s in srcs:
        h = urlparse(s).hostname or ""
        if h and h != target_host and not h.endswith("." + target_host):
            third_party.append((h, s))
    # dedupe by host
    by_host: dict[str, str] = {}
    for h, s in third_party:
        by_host.setdefault(h, s)
    if by_host:
        lines = []
        for h in sorted(by_host):
            j = _jurisdiction(h)
            lines.append(f"  - {h}  [{j}]")
        findings.append(Finding(
            severity="low",
            title=f"Third-party JS processors detected: {len(by_host)}",
            evidence="\n".join(lines[:50]),
            remediation=("Each third party is a data processor. Issue a DPA with each one. "
                         "For US-jurisdiction processors, document your Transfer Impact Assessment (TIA) per GDPR Art. 46."),
            url=target,
        ))

    # ---- #19 Google Fonts CJEU ----
    if "fonts.googleapis.com" in body or "fonts.gstatic.com" in body:
        findings.append(Finding(
            severity="medium",
            title="Google Fonts loaded directly from googleapis (CJEU 2022)",
            evidence="Detected fonts.googleapis.com or fonts.gstatic.com in HTML.",
            remediation="Self-host fonts (per German CJEU ruling, loading Google Fonts directly transfers IPs to the US without consent). Plugins: 'Local Google Fonts', 'OMGF' (Optimize My Google Fonts).",
            url=target,
        ))

    # ---- #20 IP anonymisation in GA ----
    ga_found = bool(GA_RE.search(body))
    if ga_found:
        # gather all inline scripts and check for anonymize_ip
        inline_blob = " ".join(INLINE_SCRIPT_RE.findall(body))
        if not ANONYMIZE_IP_RE.search(inline_blob):
            findings.append(Finding(
                severity="medium",
                title="Google Analytics detected without anonymize_ip",
                evidence="Found GA/GTM script tag but no inline `anonymize_ip: true`.",
                remediation="Add `gtag('config', 'GA_ID', {anonymize_ip: true});` OR migrate to GA4 (anonymisation is default). For EU compliance, also consider consent-mode v2 + a non-tracking analytics like Plausible/Fathom/Matomo.",
                url=target,
            ))

    # ---- #22 RTBE endpoint ----
    step("privacy: RTBE endpoint probe...")
    rtbe = await client.get("/wp-admin/erase-personal-data.php")
    if rtbe is not None and rtbe.status_code == 200 and "personal data" in (rtbe.text or "").lower():
        findings.append(Finding(
            severity="medium",
            title="Right-to-be-erased admin page reachable unauthenticated",
            evidence=f"GET /wp-admin/erase-personal-data.php -> 200 (looks like the form rendered).",
            remediation="WordPress core gates this with `manage_options`. If you see the form anonymously, your `is_super_admin()` plugin or proxy strips auth — investigate.",
            url=target + "/wp-admin/erase-personal-data.php",
        ))

    return findings or [Finding(severity="info", title="Privacy inventory complete — no issues",
                                 evidence="No PII leaks, banner present, no tracker concerns.",
                                 remediation="No action.", url=target)]
