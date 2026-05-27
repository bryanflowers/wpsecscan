"""A15 (v2.6.0) — S3 / R2 / GCS shadow-bucket takeover.

The existing `referenced_buckets` check probes the buckets actually
referenced from HTML. This sibling check is offensive in the opposite
direction: it predicts likely bucket names from the site's slug and
probes whether they exist + are takeable (404 on the AWS/GCS endpoint
means the operator could have used the name but didn't — attacker can
register it and serve content from that name as if from the operator).

Probe set (per bucket host):
  - {slug}-uploads, {slug}-media, {slug}-backups, {slug}-staging,
    {slug}-dev, {slug}-cdn, {slug}.uploads, uploads-{slug}

Probe response semantics differ by provider:
  - S3:  404 + "NoSuchBucket" → registerable (CRITICAL)
  - GCS: 404 + "The specified bucket does not exist" → registerable
  - R2:  generic 404 (Cloudflare); no signal — skip
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


_PROVIDERS = (
    ("s3.amazonaws.com", "S3", "NoSuchBucket"),
    ("storage.googleapis.com", "GCS", "The specified bucket does not exist"),
)

_PATTERNS = (
    "{slug}-uploads",
    "{slug}-media",
    "{slug}-backups",
    "{slug}-staging",
    "{slug}-dev",
    "{slug}-cdn",
    "{slug}-assets",
    "uploads-{slug}",
    "backups-{slug}",
)


def _slug_from_host(host: str) -> str:
    # example.com → example
    # blog.acme.co.uk → acme
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return parts[0]
    # Skip obvious sub-domains
    if parts[0] in ("www", "blog", "shop", "store", "app"):
        return parts[1] if len(parts) > 2 else parts[0]
    return parts[0]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = urlparse(client.base_url).hostname or ""
    if not host:
        return findings
    slug = _slug_from_host(host)
    if not slug or len(slug) < 3:
        return findings

    # We need an HTTP client that targets a foreign host (S3/GCS), not the
    # site under test. Use httpx directly via a new short-lived client.
    import httpx

    candidates = [p.format(slug=slug) for p in _PATTERNS]
    findings_count_before = len(findings)

    try:
        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=False,
            headers={"User-Agent": "WPSecScan/2.6.0"},
        ) as ext:
            for bucket_name in candidates:
                for provider_host, provider, marker in _PROVIDERS:
                    url = f"https://{bucket_name}.{provider_host}/"
                    step(f"shadow-bucket probe: {url}")
                    try:
                        r = await ext.get(url)
                    except (httpx.RequestError, httpx.HTTPStatusError):
                        continue
                    if r.status_code == 404 and marker in (r.text or ""):
                        findings.append(Finding(
                            severity="high",
                            title=f"{provider} bucket name takeable: {bucket_name}",
                            evidence=(
                                f"{provider} responded 404 with '{marker}' for\n"
                                f"  {url}\n"
                                f"This name resembles your site ({host}) and is\n"
                                f"unregistered. An attacker can register it and\n"
                                f"serve content from a name your customers may\n"
                                f"trust as 'official'."
                            ),
                            remediation=(
                                f"1. Register the bucket yourself at {provider} "
                                f"(cost: ~$0/month for empty bucket).\n"
                                f"2. Or, monitor for the name's registration via "
                                f"the CT-log shadow-cert check (A31) + DNS-monitoring."
                            ),
                            url=url,
                            extra={"bucket": bucket_name, "provider": provider},
                        ))
                        break  # one provider hit per name is enough
    except Exception:  # noqa: BLE001
        pass  # never break the scan on enrichment failure

    return findings
