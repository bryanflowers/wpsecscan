"""Item #79 — reference-install diff.

Compares the running site's file-monitor manifest against a known-clean
WordPress install of the same version. Every file that differs (added,
removed, or hash-mismatch) is a candidate tamper indicator.

Two inputs:

  • A *reference* tarball / zip of a clean WP install (e.g. downloaded
    fresh from wordpress.org). We compute its core-file hash manifest:
       { relative_path: sha256, ... }
    once, cached at ~/.wpsecscan/reference-installs/wp-{version}.json.

  • The *live* file-monitor manifest pulled from the companion plugin's
    `/wp-json/wpsecscan/v1/file-monitor` endpoint (already shipped).

The diff classifies every difference into one of three buckets:
  • added       — file present live but not in the reference (potential
                   shell, dropped malware, or legit plugin/theme file)
  • removed     — present in reference but missing live (could be
                   intentional core-mod or a broken install)
  • modified    — same path, different hash (highest-priority tamper
                   signal; legit core files are immutable per version)

`wpsecscan reference-diff --version 6.4.3 --live live-manifest.json
                          --reference-zip ./wordpress-6.4.3.zip`

For convenience, the CLI auto-skips known-mutable paths (wp-config.php,
.htaccess, wp-content/) so we don't flood the report with churn from
the theme + plugin folders. The user can opt in with --include-content.
"""
from __future__ import annotations

import hashlib
import json
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path


_MUTABLE_PREFIXES = (
    "wp-content/", "wp-content\\",
    "wp-config.php",
    ".htaccess",
    "robots.txt",
    "sitemap.xml",
)


def _sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _reference_cache_path(version: str) -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    d = home / "reference-installs"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"wp-{version}.json"


def build_reference_manifest(archive: Path, version: str) -> dict[str, str]:
    """Extract the archive into a temp dir and compute sha256 per file.

    Supports .zip and .tar.gz. Returns the manifest dict and caches it
    at ~/.wpsecscan/reference-installs/wp-{version}.json.
    """
    tmp = Path(tempfile.mkdtemp(prefix="wpsec-ref-"))
    try:
        if archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as zf:
                # Reject path-traversal + symlink entries before extracting
                # (same defence scan_zip.py uses for plugin .zips).
                for info in zf.infolist():
                    name = info.filename
                    if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                        raise ValueError(f"refusing to extract traversal entry: {name!r}")
                    # Symlink detection (Python <3.12 does not block these).
                    if (info.external_attr >> 16) & 0xF000 == 0xA000:
                        raise ValueError(f"refusing to extract symlink entry: {name!r}")
                zf.extractall(tmp)
        elif str(archive).lower().endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.name.startswith(("/", "\\")) or ".." in Path(member.name).parts:
                        raise ValueError(f"refusing to extract traversal entry: {member.name!r}")
                    if member.issym() or member.islnk():
                        raise ValueError(f"refusing to extract symlink/hardlink: {member.name!r}")
                # filter='data' (Python 3.12+) blocks unsafe entries even if the
                # check above misses something. Older Pythons silently accept.
                try:
                    tf.extractall(tmp, filter="data")
                except TypeError:
                    tf.extractall(tmp)  # Python <3.12
        else:
            raise ValueError("reference archive must be .zip or .tar.gz")
        # WordPress zips usually contain a top-level "wordpress/" dir.
        roots = [p for p in tmp.iterdir() if p.is_dir()]
        base = roots[0] if len(roots) == 1 else tmp
        manifest: dict[str, str] = {}
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(base).as_posix()
            manifest[rel] = _sha256_of_file(path)
        cache = _reference_cache_path(version)
        cache.write_text(json.dumps({"version": version, "files": manifest},
                                      indent=2),
                          encoding="utf-8")
        return manifest
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def load_reference_manifest(version: str) -> dict[str, str]:
    """Return the cached reference manifest, else {}."""
    p = _reference_cache_path(version)
    if not p.exists():
        return {}
    try:
        return (json.loads(p.read_text(encoding="utf-8")) or {}).get("files", {})
    except (OSError, ValueError):
        return {}


def diff_against_reference(live: dict[str, str], reference: dict[str, str],
                            *, include_content: bool = False) -> dict[str, list]:
    """Return {added: [...], removed: [...], modified: [...]}.

    Each list entry is a {path, [old_hash], [new_hash]} dict.
    """
    def _skip(p: str) -> bool:
        return any(p.startswith(prefix) for prefix in _MUTABLE_PREFIXES)

    out = {"added": [], "removed": [], "modified": []}
    live_keys = set(live)
    ref_keys = set(reference)

    for p in sorted(live_keys - ref_keys):
        if not include_content and _skip(p):
            continue
        out["added"].append({"path": p, "new_hash": live[p]})
    for p in sorted(ref_keys - live_keys):
        if not include_content and _skip(p):
            continue
        out["removed"].append({"path": p, "old_hash": reference[p]})
    for p in sorted(live_keys & ref_keys):
        if live[p] == reference[p]:
            continue
        if not include_content and _skip(p):
            continue
        out["modified"].append({"path": p, "old_hash": reference[p],
                                  "new_hash": live[p]})
    return out


def load_live_manifest(manifest_path: Path) -> dict[str, str]:
    """Read the JSON the companion /file-monitor endpoint emitted.

    Accepts both shapes the endpoint can produce:
      • {"files": {"path": "hash", ...}}        (canonical)
      • {"path": "hash", ...}                   (flat dict, very old)
    """
    raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "files" in raw and isinstance(raw["files"], dict):
        return {str(k): str(v) for k, v in raw["files"].items()}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if isinstance(v, str)}
    return {}
