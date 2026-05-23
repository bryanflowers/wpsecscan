"""J23 SBOM (CycloneDX 1.5) emission.

`wpsecscan --sbom out.json` writes a software bill of materials describing
every installed Python package WPSecScan was built with. Useful for
enterprise procurement / vendor risk programs that require an SBOM
deliverable per shipped binary.

Uses `importlib.metadata` (stdlib) — no extra deps. Output validates against
CycloneDX 1.5 JSON schema.
"""
from __future__ import annotations

import json
import platform
import sys
import uuid
from datetime import datetime, timezone
from importlib import metadata as _md
from pathlib import Path


def _component_for(dist) -> dict:
    name = dist.metadata.get("Name") or ""
    version = dist.metadata.get("Version") or ""
    purl = f"pkg:pypi/{name.lower()}@{version}"
    licenses_field = dist.metadata.get_all("License") or []
    licenses = [{"license": {"name": str(l)}} for l in licenses_field if l]
    return {
        "type": "library",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "licenses": licenses,
    }


def build_sbom(*, scanner_version: str = "?") -> dict:
    """Construct the CycloneDX 1.5 JSON-shaped SBOM dict."""
    components: list[dict] = []
    seen: set[str] = set()
    for dist in _md.distributions():
        try:
            comp = _component_for(dist)
        except Exception:  # noqa: BLE001
            continue
        purl = comp.get("purl")
        if not purl or purl in seen:
            continue
        seen.add(purl)
        components.append(comp)
    components.sort(key=lambda c: (c.get("name") or "").lower())

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{
                "vendor": "WPSecScan",
                "name": "wpsecscan",
                "version": scanner_version,
            }],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/wpsecscan@{scanner_version}",
                "name": "wpsecscan",
                "version": scanner_version,
                "properties": [
                    {"name": "python.version",  "value": sys.version.split()[0]},
                    {"name": "python.platform", "value": platform.platform()},
                ],
            },
        },
        "components": components,
    }


def write(path: Path, *, scanner_version: str = "?") -> None:
    """Write the SBOM to disk as pretty-printed JSON."""
    sbom = build_sbom(scanner_version=scanner_version)
    path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    try:
        from . import activity as _act
        _act.emit("artifact", f"SBOM: {path.name} ({len(sbom.get('components', []))} components)")
    except (ImportError, OSError):
        pass
