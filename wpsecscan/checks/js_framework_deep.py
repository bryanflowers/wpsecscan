"""Round-62 #B31 — JavaScript framework deep-detect with versions.

Detects React/Vue/Angular/Svelte/Next/Nuxt/Remix/Astro/Qwik/SolidJS by
parsing the home HTML for framework-specific markers, then extracts
versions from the main bundle URL when possible. Cross-references
versions against a minimum-safe-version pin list.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urljoin
from ..http import Client
from ..models import Finding


# Markers in HTML / inline JS / chunk URLs
DETECTORS = [
    # (framework, list of HTML markers, bundle-version regex, min safe version or None)
    ("Next.js",
        ['/_next/', "__NEXT_DATA__", "next/script", "_next/static"],
        re.compile(r"/_next/static/chunks/[^/]+/([\d.]+)\.js"),
        "14.2.0"),
    ("Nuxt 3",
        ['/_nuxt/', "__NUXT__", "nuxt-script"],
        re.compile(r"/_nuxt/[^/]+/([\d.]+)\.[a-f0-9]+\.js"),
        "3.10.0"),
    ("Gatsby",
        ['gatsby-image', 'data-gatsby-image', '/page-data/'],
        None, None),
    ("Remix",
        ['__remixManifest', 'remix.run'],
        None, "2.0.0"),
    ("Astro",
        ['astro-island', 'data-astro-cid'],
        None, None),
    ("SolidJS",
        ['solid-js', 'data-hk='],
        None, None),
    ("Qwik",
        ['q:container', 'q:base', 'data-qwik'],
        None, None),
    ("Svelte / SvelteKit",
        ['data-svelte', 'svelte-', '__SVELTEKIT_DATA__'],
        None, None),
    ("Angular",
        ['ng-version=', '_ngcontent-', '_nghost-'],
        re.compile(r'ng-version=[\"\']([\d.]+)[\"\']'),
        "17.0.0"),
    ("Vue 3",
        ['data-v-app', '__VUE_HMR_RUNTIME__'],
        None, None),
    ("React (raw)",
        ['data-reactroot', 'data-reactid', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
        None, None),
    ("Inertia.js",
        ['data-page=', 'inertia/router'],
        None, None),
]


def _ver_lt(a: str, b: str) -> bool:
    try:
        ai = [int(x) for x in re.split(r"\D+", a) if x]
        bi = [int(x) for x in re.split(r"\D+", b) if x]
        return ai < bi
    except (ValueError, TypeError):
        return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")
    step("JS framework deep-detect: GET /...")
    r = await client.get("/")
    if r is None or not r.text:
        return [Finding(severity="info", title="JS framework deep — no home page",
                        evidence="", remediation="No action.", url=target)]
    body = r.text[:500_000]
    detected: list[tuple[str, str | None, str | None]] = []   # (name, version, min_safe)
    for name, markers, version_re, min_safe in DETECTORS:
        if not any(m in body for m in markers):
            continue
        version = None
        if version_re:
            m = version_re.search(body)
            if m:
                version = m.group(1)
        detected.append((name, version, min_safe))

    if not detected:
        return [Finding(severity="info", title="JS framework deep — no SPA frameworks detected",
                        evidence=f"Probed {len(DETECTORS)} frameworks.",
                        remediation="No action.", url=target)]

    info_lines = []
    for name, version, min_safe in detected:
        info_lines.append(f"  - {name} {version or '(version unknown)'}")
        if version and min_safe and _ver_lt(version, min_safe):
            findings.append(Finding(
                severity="high",
                title=f"{name} {version} below patched baseline {min_safe}",
                evidence=f"Detected {name} {version}; min-safe {min_safe}.",
                remediation=f"Upgrade {name} to {min_safe} or later. Cross-reference with the bundled CVE DB for specifics.",
                url=target,
            ))

    findings.append(Finding(
        severity="info",
        title=f"JS frameworks detected: {len(detected)}",
        evidence="\n".join(info_lines),
        remediation="SPA frameworks bundle their own deps. Run `npm audit` or `pnpm audit` in your front-end repo.",
        url=target,
    ))
    return findings
