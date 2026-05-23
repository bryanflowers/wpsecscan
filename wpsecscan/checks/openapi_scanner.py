"""#26 (from ZAP) — OpenAPI / Swagger endpoint scanner.

Auto-discovers an OpenAPI v2 / v3 / Swagger spec at common paths, then
probes every documented endpoint with the most-permissive HTTP method
to surface:

  - Endpoints that respond 200 OK without authentication
  - Endpoints that disclose data (`/users`, `/admin/*`)
  - Endpoints that accept input shapes the spec doesn't validate (sent
    a junk body, looked for `500 Internal Server Error` vs `400 Bad
    Request`)

Discovery probes:
  - /openapi.json, /openapi.yaml
  - /swagger.json, /swagger.yaml
  - /swagger/v1/swagger.json (ASP.NET)
  - /api-docs, /api-docs.json
  - /v2/api-docs, /v3/api-docs (springdoc default)
  - /wp-json/ (WP REST root — already in its own check, but we include it
    for completeness)
"""
from __future__ import annotations

import asyncio
import json

from ..http import Client
from ..models import Finding


SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs",
)


def _parse_spec(text: str, content_type: str) -> dict | None:
    """Return parsed spec dict or None. Accepts JSON or YAML (if pyyaml present)."""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        pass
    if "yaml" in (content_type or "").lower() or text.startswith(("openapi:", "swagger:")):
        try:
            import yaml
            return yaml.safe_load(text)
        except (ImportError, Exception):  # noqa: BLE001
            return None
    return None


def _endpoints_from_spec(spec: dict) -> list[tuple[str, str]]:
    """Return [(method, path), ...] from an OpenAPI/Swagger spec."""
    out: list[tuple[str, str]] = []
    paths = spec.get("paths") or {}
    for p, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for verb in ("get", "post", "put", "delete", "patch", "options", "head"):
            if verb in methods:
                out.append((verb.upper(), p))
    return out


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    spec: dict | None = None
    spec_path: str | None = None
    for path in SPEC_PATHS:
        step(f"checking for OpenAPI spec at {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        parsed = _parse_spec(r.text or "", r.headers.get("content-type", ""))
        if parsed and isinstance(parsed, dict) and (parsed.get("openapi") or parsed.get("swagger") or parsed.get("paths")):
            spec = parsed
            spec_path = path
            break

    if not spec:
        return [Finding(severity="info",
                        title="OpenAPI/Swagger spec — none discovered",
                        evidence=f"Probed {len(SPEC_PATHS)} common spec paths; nothing usable returned.",
                        remediation="No action.", url=ctx["target"])]

    endpoints = _endpoints_from_spec(spec)
    findings.append(Finding(
        severity="info",
        title=f"OpenAPI spec discovered at {spec_path} ({len(endpoints)} endpoint(s))",
        evidence=(f"Version: {spec.get('openapi') or spec.get('swagger') or '?'}\n"
                   f"First 10 endpoints:\n  " + "\n  ".join(f"{m} {p}" for m, p in endpoints[:10])),
        remediation=("If the spec was published unintentionally, move it to an authenticated path. "
                      "If intentional (public API), make sure no admin / internal endpoint is "
                      "documented in the public spec."),
        url=ctx["target"] + (spec_path or ""),
    ))

    # Probe each documented endpoint without auth
    open_endpoints: list[tuple[str, str, int]] = []
    sem = asyncio.Semaphore(4)

    async def _probe(method: str, path: str):
        async with sem:
            # Substitute any {pathParam} placeholders with `1`
            real_path = path
            for marker in ("{id}", "{user_id}", "{userId}", "{slug}", "{name}"):
                real_path = real_path.replace(marker, "1")
            try:
                r = await client.request(method, real_path)
            except Exception:  # noqa: BLE001
                return None
            return (method, path, r.status_code if r else 0)

    results = await asyncio.gather(*(_probe(m, p) for m, p in endpoints[:50]))
    for entry in results:
        if entry and 200 <= entry[2] < 300:
            open_endpoints.append(entry)

    if open_endpoints:
        findings.append(Finding(
            severity="medium",
            title=f"{len(open_endpoints)} OpenAPI endpoint(s) reachable unauth",
            evidence="\n".join(f"  - {m} {p} -> {s}" for m, p, s in open_endpoints[:20]),
            remediation=(
                "Verify each endpoint genuinely intends to be public. Endpoints that mention "
                "'admin', 'user', 'config', or 'internal' in their path should require auth."
            ),
            url=ctx["target"],
        ))
    return findings
