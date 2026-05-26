"""Item #6 — extract cloud-bucket URLs referenced in the page HTML/JS and
probe each one for an open listing.

Complements `s3_bucket_discovery` which guesses bucket names from the
host. This check inspects what the site actually links to and asks the
question "does this referenced bucket leak its contents?" — covering
S3, Google Cloud Storage, Cloudflare R2, and DigitalOcean Spaces.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding

# Each pattern captures the *bucket* name. The host is rebuilt from match
# groups so we can normalise the listing-endpoint URL for the probe.
_BUCKET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    # https://my-bucket.s3.amazonaws.com/object
    # https://my-bucket.s3.us-west-2.amazonaws.com/object
    ("s3", re.compile(
        r"https?://([a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com",
        re.IGNORECASE)),
    # https://storage.googleapis.com/bucket-name/path
    ("gcs", re.compile(
        r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9_\-\.]{1,61}[a-z0-9])(?:/|\b)",
        re.IGNORECASE)),
    # https://bucket.account-id.r2.cloudflarestorage.com  (private endpoint)
    # https://bucket.r2.dev                                (public dev endpoint)
    ("r2", re.compile(
        r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.(?:[a-f0-9]{32}\.)?r2\.(?:cloudflarestorage\.com|dev)",
        re.IGNORECASE)),
    # https://bucket.nyc3.digitaloceanspaces.com
    # https://bucket.nyc3.cdn.digitaloceanspaces.com
    ("spaces", re.compile(
        r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.[a-z0-9\-]+(?:\.cdn)?\.digitaloceanspaces\.com",
        re.IGNORECASE)),
)

_SCAN_PATHS = ("/", "/?p=1", "/sample-page/", "/feed/", "/shop/")

# Per-provider listing-endpoint builder.
def _list_url(provider: str, bucket: str, full_match: str) -> str | None:
    if provider == "s3":
        # Use the global endpoint — it redirects to the correct region.
        return f"https://{bucket}.s3.amazonaws.com/?list-type=2"
    if provider == "gcs":
        # The XML listing endpoint is at the root of the bucket.
        return f"https://storage.googleapis.com/{bucket}?prefix=&max-results=1"
    if provider == "r2":
        # R2 dev endpoints don't support XML listing; HEAD the bucket root
        # — public-bucket misconfig surfaces as 200 instead of 401.
        host_match = re.search(r"https?://[^/]+", full_match)
        return host_match.group(0) + "/" if host_match else None
    if provider == "spaces":
        host_match = re.search(r"https?://[^/]+", full_match)
        return (host_match.group(0) + "/?list-type=2") if host_match else None
    return None


def _is_listing_response(provider: str, status: int, body: bytes) -> bool:
    """Heuristic: did the probe return a real bucket listing?"""
    if status != 200:
        return False
    head = body[:512].lower()
    if provider == "s3" or provider == "spaces":
        return b"<listbucketresult" in head or b"<?xml" in head and b"contents" in head
    if provider == "gcs":
        return b"<listbucketresult" in head or b"<contents>" in head or b"<name>" in head
    if provider == "r2":
        # R2 doesn't list by default; a 200 with HTML/text from the root path
        # is unusual and suggests a misconfigured public bucket worth flagging.
        return True
    return False


async def _probe(bclient: httpx.AsyncClient, provider: str, bucket: str,
                  full_match: str) -> dict | None:
    url = _list_url(provider, bucket, full_match)
    if not url:
        return None
    try:
        r = await bclient.get(url)
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
    body = r.content or b""
    return {
        "provider": provider,
        "bucket": bucket,
        "url": url,
        "status": r.status_code,
        "listing": _is_listing_response(provider, r.status_code, body),
        "size": len(body),
    }


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Gather bodies — we don't need to be exhaustive; a few key pages cover
    # most public asset references on a typical WP site.
    bodies: list[str] = []
    for path in _SCAN_PATHS:
        step(f"fetching {path} for bucket references...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        bodies.append(r.text)

    if not bodies:
        return findings

    # Extract unique (provider, bucket) tuples + the original match so we
    # can rebuild the listing URL with the right region/host.
    seen: set[tuple[str, str]] = set()
    candidates: list[tuple[str, str, str]] = []  # (provider, bucket, full_match)
    for body in bodies:
        for provider, pat in _BUCKET_PATTERNS:
            for m in pat.finditer(body):
                bucket = m.group(1).lower()
                key = (provider, bucket)
                if key in seen:
                    continue
                seen.add(key)
                # Re-extract the URL portion of the match for host reconstruction.
                full = m.group(0)
                candidates.append((provider, bucket, full))

    if not candidates:
        findings.append(
            Finding(
                severity="info",
                title="No cloud-bucket URLs referenced in page source",
                evidence=f"Scanned {len(bodies)} pages for S3 / GCS / R2 / Spaces references.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    step(f"probing {len(candidates)} referenced bucket(s) for open listings...")
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False,
                                  headers={"User-Agent": "WPSecScan/bucket-probe"}) as bclient:
        tasks = [_probe(bclient, p, b, f) for p, b, f in candidates]
        results = [r for r in await asyncio.gather(*tasks, return_exceptions=False) if r]

    # Emit one finding per probed bucket. Listable → high; existing-private → info.
    n_listable = 0
    for r in results:
        if r["listing"]:
            n_listable += 1
            findings.append(
                Finding(
                    severity="high",
                    title=f"{r['provider'].upper()} bucket publicly listable: {r['bucket']}",
                    evidence=(
                        f"GET {r['url']} -> HTTP {r['status']} ({r['size']} bytes).\n"
                        "The bucket is referenced from this site and its contents can be enumerated "
                        "by any anonymous visitor. Leaked object keys often expose customer IDs, "
                        "internal filenames, database dumps, or staged backups."
                    ),
                    remediation=_remediation(r["provider"]),
                    url=r["url"],
                    extra={"provider": r["provider"], "bucket": r["bucket"]},
                )
            )

    if not n_listable:
        findings.append(
            Finding(
                severity="info",
                title=f"{len(candidates)} referenced bucket(s) — none publicly listable",
                evidence=(
                    "Probed each referenced bucket; none returned an enumerable listing. "
                    f"Buckets seen: {', '.join(sorted({b for _, b, _ in candidates}))[:200]}"
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
    return findings


def _remediation(provider: str) -> str:
    if provider == "s3":
        return (
            "AWS Console -> S3 -> the bucket -> Permissions -> Block public access -> "
            "enable all four blocks. Verify with `aws s3api get-public-access-block`."
        )
    if provider == "gcs":
        return (
            "GCP Console -> Cloud Storage -> the bucket -> Permissions -> remove the "
            "allUsers / allAuthenticatedUsers principal. Set Uniform bucket-level access ON "
            "to prevent per-object ACL drift."
        )
    if provider == "r2":
        return (
            "Cloudflare dashboard -> R2 -> the bucket -> Settings -> disable 'Public access' "
            "(or remove the custom-domain binding if it's serving the bucket root). "
            "Use signed URLs for downloads instead."
        )
    if provider == "spaces":
        return (
            "DigitalOcean control panel -> Spaces -> the bucket -> Settings -> File listing "
            "set to 'Restricted'. Verify with `s3cmd info s3://NAME` after rotating any keys."
        )
    return "Restrict bucket listing in the provider's permissions panel."
