"""composer.lock exposure + known-vulnerable-version detection.

Round-64 #59 — many WP devs run `composer install` at the docroot,
which leaks composer.lock + composer.json. The file is read-only but
discloses every PHP-dependency version, making vuln-mapping trivial for
an attacker. We probe a handful of likely paths and, if exposed, parse
the lock for a small curated list of high-impact known-vulnerable
versions.
"""
from __future__ import annotations

import json

from ..http import Client
from ..models import Finding

# Known-vulnerable Packagist packages (curated, high-impact only).
# (package, max-vulnerable-version, CVE/ref)
_KNOWN_VULN = (
    ("guzzlehttp/guzzle", "7.4.4", "CVE-2022-29248 cookie-header leak"),
    ("symfony/http-foundation", "5.4.10", "CVE-2022-24894 cache-key smuggling"),
    ("phpmailer/phpmailer", "6.5.0", "CVE-2021-34551 RCE via attachment"),
    ("laravel/framework", "9.1.8", "CVE-2022-23517 password reset"),
    ("doctrine/dbal", "3.3.4", "CVE-2022-31043 SQL injection in LIKE"),
    ("monolog/monolog", "2.4.0", "CVE-2022-24818 file-handler PHP-tag"),
    ("twig/twig", "3.4.0", "CVE-2022-23614 sandbox bypass"),
)

_PROBE_PATHS = (
    "/composer.lock",
    "/composer.json",
    "/wp-content/composer.lock",
    "/vendor/composer.lock",
)


def _version_le(a: str, b: str) -> bool:
    """Compare two SemVer-ish strings ignoring extras. Returns a <= b."""
    def _tup(v: str) -> tuple:
        return tuple(int(x) for x in v.split("-", 1)[0].split(".") if x.isdigit())
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
        if len(body) < 50:
            continue
        # Only treat as composer.lock if it has the canonical top-level keys
        is_lock = '"packages"' in body and '"content-hash"' in body
        is_json = '"name"' in body and '"require"' in body
        if not (is_lock or is_json):
            continue

        findings.append(
            Finding(
                severity="medium" if is_lock else "low",
                title=f"composer dependency file exposed at {path}",
                evidence=f"GET {path} -> 200 ({len(body)} bytes)",
                remediation=(
                    "Block public access to composer.lock / composer.json:\n"
                    "  Apache:  <Files ~ \"composer\\.(json|lock)$\"> Require all denied </Files>\n"
                    "  Nginx:   location ~* /composer\\.(json|lock)$ { deny all; }\n"
                    "Then audit the listed dependencies for known CVEs (composer audit)."
                ),
                url=client.url(path),
            )
        )

        if is_lock:
            try:
                data = json.loads(body)
                for pkg in data.get("packages", []) + data.get("packages-dev", []):
                    pkg_name = pkg.get("name", "")
                    pkg_ver = (pkg.get("version", "") or "").lstrip("vV")
                    for name, max_vuln, ref in _KNOWN_VULN:
                        if pkg_name == name and pkg_ver and _version_le(pkg_ver, max_vuln):
                            findings.append(
                                Finding(
                                    severity="high",
                                    title=f"Known-vulnerable dependency: {pkg_name} {pkg_ver}",
                                    evidence=f"composer.lock declares {pkg_name} @ {pkg_ver}\n  CVE: {ref}",
                                    remediation=f"Run: composer update {pkg_name} -- pin to > {max_vuln}",
                                    url=client.url(path),
                                    extra={"package": pkg_name, "version": pkg_ver, "cve": ref},
                                )
                            )
            except (ValueError, TypeError, KeyError):
                pass

    return findings
