"""Email-obfuscation library detection + raw-email-still-in-source check.

Many sites install a JS library that "obfuscates" email addresses on the
front-end (Cloudflare email protection, Anti-Spam Email, Email Encoder
Bundle, etc). Two problems:
  1. The obfuscation is trivially reversible (all client-side); spam
     scrapers cracked these years ago.
  2. The raw email is often STILL present somewhere in the HTML / JS
     bundle, defeating the obfuscation.
  3. Screen readers break on obfuscated `mailto:` links → a11y regression.
"""
from __future__ import annotations
import re
from ..http import Client
from ..models import Finding


# Detection patterns for popular obfuscation libraries.
_OBFUSCATORS = (
    ("Cloudflare email protection",  re.compile(r"/cdn-cgi/l/email-protection|email-decode\.min\.js")),
    ("WP Email Encoder Bundle",      re.compile(r"freischalter|wpencoder|EmailEncoderBundle")),
    ("Anti-Spam Email",              re.compile(r"antispambot|antispam-bee|/wp-content/plugins/anti-spam[^/]*/")),
)
# Find a raw email address in any text. Greedy enough to catch most things.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("scanning homepage for email-obfuscation libraries...")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    detected: list[str] = []
    for name, rx in _OBFUSCATORS:
        if rx.search(r.text):
            detected.append(name)
    if not detected:
        return findings
    raw_emails = set(_EMAIL_RE.findall(r.text))
    # Strip the obvious noise — wordpress.org / w3.org / cloudflare.com /
    # noreply addresses are usually framework or vendor URLs, not the site's
    # contact addresses.
    noisy_domains = ("wordpress.org", "w3.org", "cloudflare.com", "example.com",
                     "example.org", "noreply", "no-reply")
    real_leaks = [e for e in raw_emails
                  if not any(n in e.lower() for n in noisy_domains)]
    sev = "low" if real_leaks else "info"
    if real_leaks:
        ev = (
            f"Obfuscator detected: {', '.join(detected)}\n"
            f"But these raw email addresses are STILL present in the page source "
            f"(obfuscation defeated):\n"
            + "\n".join(f"  - {e[:5]}{'*' * max(0, len(e) - 5)}" for e in sorted(real_leaks)[:10])
        )
    else:
        ev = (f"Obfuscator detected: {', '.join(detected)}. No raw email "
              "addresses detected alongside it.")
    findings.append(Finding(
        severity=sev,
        title=("Email obfuscation in use but raw addresses still leak"
               if real_leaks else "Email-obfuscation library in use (information only)"),
        evidence=ev,
        remediation=(
            "Client-side email obfuscation is cosmetic — all current libraries "
            "are trivially reversed by modern scrapers. The right defences are:\n"
            "1. Use a contact form (no mailto: anywhere)\n"
            "2. Image-based addresses for low-volume contact pages\n"
            "3. Trust your spam filter (Gmail/Microsoft do this well)\n"
            "Obfuscation also breaks screen readers (a11y regression). Verify the "
            "obfuscator's mailto: output passes accessibility audits."
        ),
        url=ctx["target"],
        extra={"libraries": detected, "leak_count": len(real_leaks)},
    ))
    return findings
