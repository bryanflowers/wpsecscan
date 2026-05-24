"""Helm / docker-compose / k8s manifest exposure scan.

Round-64 #68 — WP sites deployed via Helm + k8s sometimes leak the
values.yaml / docker-compose.yml in the docroot (someone runs
`helm template` and forgets to .gitignore the output, or a
docker-compose.yml ends up under public_html). These files commonly
contain image SHAs, environment variables (=> secrets), and internal
service names that aid lateral movement.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

_PROBE_PATHS = (
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/docker-compose.prod.yml",
    "/docker-compose.override.yml",
    "/helm/values.yaml",
    "/values.yaml",
    "/values.prod.yaml",
    "/kustomization.yaml",
    "/k8s/deployment.yaml",
    "/.kube/config",
    "/Chart.yaml",
)

_SECRET_PATTERNS = (
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                "AWS access key"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}"),          "Stripe live secret"),
    (re.compile(r"password\s*:\s*\S{4,}", re.IGNORECASE), "YAML password field"),
    (re.compile(r"db_password\s*:\s*\S{4,}", re.IGNORECASE), "DB password"),
    (re.compile(r"api_key\s*:\s*\S{8,}", re.IGNORECASE), "Generic API key"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"), "Private key"),
)


def _looks_like_yaml(body: str) -> bool:
    """At least one indented YAML key — and not just HTML."""
    if "<html" in body.lower()[:200] or "<!doctype" in body.lower()[:200]:
        return False
    has_keys = re.search(r"^\s*[a-zA-Z_][a-zA-Z0-9_-]*\s*:\s*\S", body, re.MULTILINE)
    return has_keys is not None


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if len(body) < 30 or not _looks_like_yaml(body):
            continue

        # Distinguish docker-compose vs helm values vs k8s manifest
        if "services:" in body or "version:" in body[:60]:
            kind = "docker-compose"
        elif "apiVersion:" in body or "kind:" in body:
            kind = "k8s-manifest"
        elif "apiVersion: v" in body[:200]:
            kind = "helm-chart"
        else:
            kind = "yaml-config"

        findings.append(
            Finding(
                severity="medium",
                title=f"{kind} file exposed at {path}",
                evidence=f"GET {path} -> 200 ({len(body)} bytes); shape: {kind}",
                remediation=(
                    f"Block {kind} files publicly. These leak image SHAs, service names + ports, "
                    "env-var keys (and sometimes values). Add a deny rule in your web-server config "
                    "matching *.yml + *.yaml above the docroot."
                ),
                url=client.url(path),
            )
        )

        for pat, name in _SECRET_PATTERNS:
            if pat.search(body):
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"{name} leaked in {path}",
                        evidence=f"Pattern {name!r} matched in {path}",
                        remediation=f"ROTATE the {name} immediately. Move secrets out of the YAML into a separate Secret object (k8s) or .env (compose).",
                        url=client.url(path),
                        extra={"secret_type": name},
                    )
                )

    return findings
