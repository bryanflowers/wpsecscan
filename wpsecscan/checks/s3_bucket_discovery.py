"""S3 bucket discovery + ACL scan.

Generates likely S3 bucket names from the target's hostname using common
suffixes/prefixes (-backup, -uploads, -media, -static, -assets, -prod, -staging).
For each guessed name, attempts:
  1. `GET https://<bucket>.s3.amazonaws.com/?list-type=2` — public LIST ACL
  2. `HEAD https://<bucket>.s3.amazonaws.com/` — bucket existence

Reports public-readable buckets as high; existing-but-private as info.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding

NAME_VARIANTS = (
    "{base}",
    "{base}-backup", "{base}-backups", "{base}-bkp",
    "{base}-uploads", "{base}-media", "{base}-assets",
    "{base}-static", "{base}-img", "{base}-images",
    "{base}-prod", "{base}-staging", "{base}-dev",
    "{base}-data", "{base}-files", "{base}-docs",
    "{base}-www", "{base}-cdn", "{base}-store",
    "backup-{base}", "backups-{base}", "media-{base}", "static-{base}",
    "{base}-wp", "{base}-wordpress",
)

REGIONS_TO_TRY = ("s3.amazonaws.com",)  # the global endpoint redirects to the bucket's region


async def _probe_bucket(client: httpx.AsyncClient, name: str) -> dict | None:
    """Probe one bucket name. Returns dict with status info, or None if it doesn't exist."""
    url = f"https://{name}.s3.amazonaws.com/?list-type=2"
    try:
        r = await client.get(url)
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
    if r.status_code == 404:
        return None  # bucket doesn't exist
    if r.status_code == 200:
        return {"name": name, "public_list": True, "status": 200,
                "size": len(r.content or b"")}
    if r.status_code == 403:
        # Exists but not publicly listable; could still have readable objects
        return {"name": name, "public_list": False, "status": 403}
    if r.status_code in (301, 307):
        return {"name": name, "redirected": True, "status": r.status_code,
                "location": r.headers.get("location", "")}
    return {"name": name, "status": r.status_code}


def _base_name(host: str) -> str:
    """Strip TLD + 'www.' to derive a bucket-base from a hostname.

    `www.mysite.co.uk` -> `mysite`. Best-effort; some users may run their bucket
    under the full apex (mysite-co-uk) so we ALSO try that.
    """
    h = host.lower()
    if h.startswith("www."):
        h = h[4:]
    parts = h.split(".")
    if len(parts) >= 2:
        return parts[0]
    return h


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(ctx["target"]).hostname or ""
    if not host:
        findings.append(
            Finding(
                severity="info",
                title="S3 bucket discovery skipped — no host",
                evidence=f"target: {ctx['target']}",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    base = _base_name(host)
    # Also try the apex with dots-to-dashes (e.g. mysite-com)
    apex_dashed = host.replace("www.", "").replace(".", "-")
    candidates = sorted({tmpl.format(base=b) for b in (base, apex_dashed) for tmpl in NAME_VARIANTS})

    step(f"probing {len(candidates)} candidate S3 bucket names...")
    results: list[dict] = []
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False,
                                  headers={"User-Agent": "WPSecScan/s3-discover"}) as bclient:
        tasks = [_probe_bucket(bclient, name) for name in candidates]
        for r in await asyncio.gather(*tasks, return_exceptions=False):
            if r is not None:
                results.append(r)

    if not results:
        findings.append(
            Finding(
                severity="info",
                title=f"No S3 buckets found matching {len(candidates)} naming patterns for {host}",
                evidence=f"Tried: {', '.join(candidates[:8])}...",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for r in results:
        name = r["name"]
        url = f"https://{name}.s3.amazonaws.com/"
        if r.get("public_list"):
            findings.append(
                Finding(
                    severity="high",
                    title=f"S3 bucket publicly LISTABLE: {name}",
                    evidence=(
                        f"GET {url}?list-type=2 -> HTTP 200 ({r.get('size', '?')} bytes of XML).\n"
                        "Anyone can enumerate all object keys in the bucket. Even if objects are private, "
                        "leaking the key names alone often reveals customer IDs / filenames / db dumps."
                    ),
                    remediation=(
                        "AWS Console -> S3 -> the bucket -> Permissions -> Block public access -> "
                        "enable all four blocks. Verify with `aws s3api get-public-access-block`."
                    ),
                    url=url,
                )
            )
        elif r.get("status") == 403:
            findings.append(
                Finding(
                    severity="low",
                    title=f"S3 bucket exists (private list-ACL): {name}",
                    evidence=(
                        f"GET {url} -> 403 (bucket exists, but list-ACL is private — good).\n"
                        "Audit object-level ACLs separately: a bucket can be list-private but have public objects."
                    ),
                    remediation=(
                        "Verify object-level public access is also blocked. AWS Trusted Advisor "
                        "or `aws s3api list-objects --bucket NAME` (as bucket owner) confirms."
                    ),
                    url=url,
                )
            )
        elif r.get("redirected"):
            findings.append(
                Finding(
                    severity="info",
                    title=f"S3 bucket exists (in a different region): {name}",
                    evidence=f"Redirect to: {r.get('location', '?')[:120]}",
                    remediation="No action — bucket presence noted for context.",
                    url=url,
                )
            )
    return findings
