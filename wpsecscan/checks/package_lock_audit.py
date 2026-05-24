"""package-lock.json / yarn.lock / pnpm-lock.yaml exposure audit.

Round-64 #60 — themes + build pipelines often leave Node lockfiles in
the docroot. Same risk profile as composer.lock: discloses every
dependency + exact version, plus the resolved registry URL (which may
itself include an auth token).
"""
from __future__ import annotations

import json
import re

from ..http import Client
from ..models import Finding

# Common high-impact known-vulnerable npm packages, by max-vulnerable
# version. Tiny curated list — full audit would defer to OSV/Snyk
# upstream, which the aggregator already covers.
_KNOWN_VULN = (
    ("lodash", "4.17.20", "CVE-2021-23337 command injection"),
    ("axios", "0.21.0", "CVE-2020-28168 SSRF"),
    ("minimist", "1.2.5", "CVE-2021-44906 prototype pollution"),
    ("ansi-regex", "5.0.0", "CVE-2021-3807 ReDoS"),
    ("ws", "7.4.5", "CVE-2021-32640 ReDoS"),
    ("json5", "2.2.1", "CVE-2022-46175 prototype pollution"),
    ("semver", "7.5.1", "CVE-2022-25883 ReDoS in new Range"),
    ("loader-utils", "2.0.4", "CVE-2022-37601 prototype pollution"),
)

_PROBE_PATHS = (
    "/package.json",
    "/package-lock.json",
    "/wp-content/themes/twentytwentyfour/package.json",
    "/wp-content/package.json",
)


def _version_le(a: str, b: str) -> bool:
    def _tup(v: str) -> tuple:
        return tuple(int(x) for x in v.split("-", 1)[0].lstrip("^~=v").split(".") if x.isdigit())
    try:
        return _tup(a) <= _tup(b)
    except ValueError:
        return False


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        # Heuristic: must look like npm-style JSON
        if not (body.lstrip().startswith("{") and ('"dependencies"' in body or '"packages"' in body or '"name"' in body)):
            continue

        findings.append(
            Finding(
                severity="medium" if "lock" in path else "low",
                title=f"npm dependency file exposed at {path}",
                evidence=f"GET {path} -> 200 ({len(body)} bytes)",
                remediation=(
                    "Block public access to package*.json / yarn.lock / pnpm-lock.yaml.\n"
                    "  Apache: <FilesMatch \"^(package(-lock)?\\.json|yarn\\.lock|pnpm-lock\\.yaml)$\"> Require all denied </FilesMatch>\n"
                    "  Nginx:  location ~* ^/(package(-lock)?\\.json|yarn\\.lock|pnpm-lock\\.yaml)$ { deny all; }"
                ),
                url=client.url(path),
            )
        )

        # Scan auth tokens leaked in resolved URLs (top reason to deny these)
        m = re.search(r'(npmjs\.org|nodejs\.org|github\.com)/[^"\s]*[?&]?(token|key)=([A-Za-z0-9_\-]{20,})', body)
        if m:
            findings.append(
                Finding(
                    severity="high",
                    title="npm registry auth token leaked in resolved URL",
                    evidence=f"Found pattern {m.group(0)[:60]!r}... in {path}",
                    remediation="Rotate the npm/GitHub token immediately. Block public access to the lockfile.",
                    url=client.url(path),
                )
            )

        # Known-CVE matching
        try:
            data = json.loads(body)
            deps = {}
            if "dependencies" in data and isinstance(data["dependencies"], dict):
                deps.update({k: (v if isinstance(v, str) else (v.get("version", "") if isinstance(v, dict) else ""))
                             for k, v in data["dependencies"].items()})
            if "packages" in data and isinstance(data["packages"], dict):
                for k, v in data["packages"].items():
                    name = k.split("node_modules/")[-1] if "node_modules" in k else k
                    if isinstance(v, dict):
                        deps[name] = v.get("version", "")
            for name, ver in deps.items():
                if not ver or not isinstance(ver, str):
                    continue
                for vn, max_vuln, ref in _KNOWN_VULN:
                    if name == vn and _version_le(ver, max_vuln):
                        findings.append(
                            Finding(
                                severity="high",
                                title=f"Known-vulnerable npm dep: {name}@{ver}",
                                evidence=f"{path} declares {name} @ {ver}\n  CVE: {ref}",
                                remediation=f"npm update {name} (must be > {max_vuln})",
                                url=client.url(path),
                                extra={"package": name, "version": ver, "cve": ref},
                            )
                        )
        except (ValueError, TypeError, KeyError):
            pass

    return findings
