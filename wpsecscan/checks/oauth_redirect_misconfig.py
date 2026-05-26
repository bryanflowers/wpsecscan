"""OAuth misconfig: extract client_id + redirect_uri from Google/Facebook/Apple
login flows discovered on the site and flag staging/localhost redirect URIs.

When oauth_oidc detects a Sign-in-with-Google button etc., this check pulls
the redirect_uri parameter from the discovered authorisation URL and looks
for staging/localhost markers. Production OAuth apps with non-production
redirects can accept tokens for any redirect (depending on provider) — a
phishing-prep vector.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs
from ..http import Client
from ..models import Finding


_OAUTH_LINK_RE = re.compile(
    r'href=[\"\']([^\"\']*(?:accounts\.google\.com/o/oauth2|'
    r'facebook\.com/v\d+\.\d+/dialog/oauth|'
    r'appleid\.apple\.com/auth/authorize)[^\"\']*)',
    re.IGNORECASE,
)

_SUSPECT_TOKENS = ("staging", "stage", "localhost", "127.0.0.1",
                   "0.0.0.0", "-dev", "_dev", ".dev", "internal",
                   ".local", ".lan")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    step("looking for OAuth login flows on /...")
    r = await client.get("/")
    if r is None or not r.text:
        return findings
    findings_by_provider: dict[str, list[tuple[str, str]]] = {}
    for m in _OAUTH_LINK_RE.finditer(r.text):
        auth_url = m.group(1).replace("&amp;", "&")
        parsed = urlparse(auth_url)
        provider = "Google" if "google.com" in parsed.netloc else \
                   "Facebook" if "facebook.com" in parsed.netloc else \
                   "Apple" if "apple.com" in parsed.netloc else "OAuth"
        qs = parse_qs(parsed.query)
        client_id = (qs.get("client_id") or [""])[0]
        redirect_uri = (qs.get("redirect_uri") or [""])[0]
        if not redirect_uri:
            continue
        # Decode percent-encoded URI
        try:
            from urllib.parse import unquote
            redirect_uri_decoded = unquote(redirect_uri)
        except Exception:  # noqa: BLE001
            redirect_uri_decoded = redirect_uri
        host = (urlparse(redirect_uri_decoded).hostname or "").lower()
        if any(tok in host for tok in _SUSPECT_TOKENS):
            findings_by_provider.setdefault(provider, []).append(
                (client_id[:12] + "..." if client_id else "(no client_id)", redirect_uri_decoded[:120])
            )
    if not findings_by_provider:
        return findings
    for provider, entries in findings_by_provider.items():
        for client_id, uri in entries[:5]:  # cap per provider
            findings.append(Finding(
                severity="medium",
                title=f"{provider} OAuth redirect_uri points at staging/localhost host",
                evidence=(
                    f"OAuth flow on homepage uses:\n"
                    f"  client_id:   {client_id}\n"
                    f"  redirect_uri: {uri}\n\n"
                    "A production OAuth flow with a staging/localhost redirect_uri "
                    "indicates either a misconfigured OAuth app (accepting tokens "
                    "for non-production destinations) or a copy-paste error that "
                    "shipped to production. Either way, fix it before someone "
                    "uses it as a phishing prep."
                ),
                remediation=(
                    f"1. Verify the OAuth app at the {provider} developer console "
                    "and confirm the registered redirect URI list contains ONLY "
                    "production URLs.\n"
                    "2. If staging/localhost was needed during testing, register a "
                    f"separate OAuth app for staging and use different client_id "
                    "values per environment.\n"
                    "3. Audit recent OAuth callbacks for hits against the staging "
                    "URI — those are users who may have been redirected away from "
                    "your real domain mid-authentication."
                ),
                url=ctx["target"],
            ))
    return findings
