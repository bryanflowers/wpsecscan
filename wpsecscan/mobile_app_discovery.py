"""#38 — Mobile-app endpoint discovery.

A target's official iOS/Android app usually talks to the same backend
the website does, but uses internal API endpoints the public docs
don't mention. We discover those endpoints from two sources:

  1. **App-link / app-site-association files** — both iOS and Android
     publish these on the target's domain to register universal links.
     iOS: `/.well-known/apple-app-site-association` (or `/apple-app-site-association`)
     Android: `/.well-known/assetlinks.json`

  2. **App store metadata** — if the user supplies an App Store / Play
     Store URL via `--mobile-app-url`, we fetch the public metadata
     page and look for hard-coded API URL references in the description
     / changelog.

This module focuses on (1) — the assoc files. (2) requires per-store
scraping that's flaky (HTML changes); deferred.
"""
from __future__ import annotations

import json

from .http import Client


ASSOC_PATHS = (
    "/.well-known/apple-app-site-association",
    "/apple-app-site-association",
    "/.well-known/assetlinks.json",
)


async def discover(client: Client) -> dict:
    """Return {found_paths, endpoints} from the target's mobile-app assoc files."""
    out_endpoints: set[str] = set()
    out_paths: list[str] = []
    for p in ASSOC_PATHS:
        r = await client.get(p)
        if r is None or r.status_code != 200:
            continue
        out_paths.append(p)
        try:
            data = json.loads(r.text or "{}")
        except (ValueError, json.JSONDecodeError):
            continue
        # iOS assoc: applinks.details[].paths is a list of glob patterns
        for det in (data.get("applinks", {}).get("details", []) or []):
            for endpoint in det.get("paths", []) or []:
                out_endpoints.add(str(endpoint))
        # Android assoc: list of {namespace, package_name, sha256_cert_fingerprints, target}
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and "target" in entry:
                    # Android format doesn't list endpoint paths directly, but the
                    # package_name + sha256 fingerprint are interesting metadata
                    pn = (entry.get("target", {}).get("package_name") or "")
                    if pn:
                        out_endpoints.add(f"(android pkg: {pn})")
    return {"found_paths": out_paths, "endpoints": sorted(out_endpoints)}
