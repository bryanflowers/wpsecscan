"""GitHub leaked-token search.

Queries GitHub's code-search API for the target's domain combined with common
secret prefixes (`AKIA`, `sk_live_`, `ghp_`, etc). If anything's been committed,
GitHub finds it.

Opt-in: requires `--github-search-token` (a GitHub PAT with `public_repo` scope).
The PAT is needed because the code-search API requires auth.
"""
from __future__ import annotations

import json as _json
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

# Each tuple = (search query template, label)
SECRET_QUERIES = (
    ('"{host}" "AKIA"', "AWS Access Key"),
    ('"{host}" "sk_live_"', "Stripe live key"),
    ('"{host}" "ghp_"', "GitHub PAT (classic)"),
    ('"{host}" "github_pat_"', "GitHub PAT (fine-grained)"),
    ('"{host}" "AIza"', "Google API key"),
    ('"{host}" "xoxb-"', "Slack bot token"),
    ('"{host}" "xoxp-"', "Slack user token"),
    ('"{host}" "SG."', "SendGrid API key"),
    ('"{host}" "shpat_"', "Shopify access token"),
    ('"{host}" "EAA"', "Facebook access token"),
)


def _gh_search(query: str, token: str, timeout: float = 10.0) -> list[dict] | None:
    """Query api.github.com/search/code. Returns items list or None on error."""
    url = "https://api.github.com/search/code?" + urllib.parse.urlencode({"q": query, "per_page": "5"})
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "WPSecScan/gh-leak-search",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = _json.loads(resp.read().decode("utf-8"))
            return data.get("items", []) or []
    except (HTTPError, URLError, OSError, ValueError):
        return None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    token = (ctx.get("github_search_token") or "").strip()
    if not token:
        findings.append(
            Finding(
                severity="info",
                title="GitHub leaked-token search skipped (no PAT)",
                evidence=(
                    "Pass --github-search-token YOUR_PAT to enable. PAT needs `public_repo` scope. "
                    "GitHub's code-search API requires auth (60 req/hour for the search endpoint)."
                ),
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    host = urlparse(ctx["target"]).hostname or ""
    if not host:
        return findings

    import asyncio
    # We run each query serially to stay under GitHub's 30-req/min code-search limit
    hits_per_query: dict[str, list[dict]] = {}
    for tmpl, label in SECRET_QUERIES:
        q = tmpl.format(host=host)
        step(f"GitHub code-search: {label}...")
        items = await asyncio.to_thread(_gh_search, q, token)
        if items:
            hits_per_query[label] = items

    if not hits_per_query:
        findings.append(
            Finding(
                severity="info",
                title=f"GitHub code-search clean for {host}",  # noqa
                evidence=f"Ran {len(SECRET_QUERIES)} secret-prefix queries; no matches.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for label, items in hits_per_query.items():
        sample = items[0]
        repo = sample.get("repository", {}).get("full_name", "?")
        path = sample.get("path", "?")
        html_url = sample.get("html_url", f"https://github.com/search?q={urllib.parse.quote(host)}")
        findings.append(
            Finding(
                severity="critical",
                title=f"Possible {label} leak: {host} mentioned in {repo}/{path}",
                evidence=(
                    f"GitHub code-search returned {len(items)} match(es) for `{host}` AND a {label} "
                    f"prefix.\nFirst match: {html_url}\n\n"
                    "This DOES NOT prove a real key is leaked — the match could be a placeholder, a "
                    "comment, or coincidence — but it's a HIGH-PRIORITY manual check."
                ),
                remediation=(
                    "1. Open the link above and read the file.\n"
                    "2. If it's a real key — rotate it RIGHT NOW (Stripe / AWS / GitHub / etc).\n"
                    "3. Run `git log --all --full-history -p -- <file>` to confirm the key isn't still "
                    "in the repo history (rotation invalidates the key but git history retains it)."
                ),
                url=html_url,
                extra={"github_search_count": len(items), "first_repo": repo, "first_path": path},
            )
        )
    return findings
