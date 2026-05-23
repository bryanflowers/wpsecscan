"""#17 (from nuclei) — community-template signature verification.

When the community templates land in ~/.wpsecscan/templates/, users want
to know they haven't been tampered with mid-flight. We support two
verification modes:

  1. **SHA256 manifest** — a sibling file `templates.sha256` in the same
     directory lists `<sha256>  <filename>` lines (output of
     `sha256sum *.yaml > templates.sha256`). On load we re-hash each
     template and reject mismatches.

  2. **GPG-signed manifest** — `templates.sha256.asc` is the detached
     signature of `templates.sha256` from a trusted key (fingerprint
     pinned in WPSECSCAN_TEMPLATE_SIGNER env). Requires `gpg` on PATH;
     falls back to SHA256-only when gpg isn't present.

Tampered templates are skipped + a high-severity warning is emitted via
the activity bus.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path


def _manifest_path(templates_dir: Path) -> Path:
    return templates_dir / "templates.sha256"


def _signature_path(templates_dir: Path) -> Path:
    return templates_dir / "templates.sha256.asc"


def load_manifest(templates_dir: Path) -> dict[str, str]:
    """Parse `<sha>  <filename>` lines. Returns {filename: sha256}.
    Returns {} when no manifest exists."""
    p = _manifest_path(templates_dir)
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and len(parts[0]) == 64:
                out[parts[1]] = parts[0].lower()
    except OSError:
        pass
    return out


def verify_signature(templates_dir: Path) -> tuple[bool, str]:
    """Return (gpg_ok, message). Tries `gpg --verify`."""
    sig = _signature_path(templates_dir)
    manifest = _manifest_path(templates_dir)
    if not sig.exists() or not manifest.exists():
        return (False, "no signature file present")
    if not shutil.which("gpg"):
        return (False, "gpg not on PATH — signature skipped (SHA256 manifest still enforced)")
    try:
        proc = subprocess.run(
            ["gpg", "--verify", str(sig), str(manifest)],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            pinned = os.environ.get("WPSECSCAN_TEMPLATE_SIGNER", "").strip().lower()
            if pinned:
                if pinned.replace(" ", "") in proc.stderr.replace(" ", "").lower():
                    return (True, "gpg signature valid + signer fingerprint matches pin")
                return (False, "gpg signature valid but signer doesn't match WPSECSCAN_TEMPLATE_SIGNER pin")
            return (True, "gpg signature valid (no pin set — any signature accepted)")
        # Strip non-printable ASCII so embedded ANSI escapes / control bytes
        # from gpg can't corrupt the downstream renderers (console, GUI, HTML).
        cleaned = "".join(c for c in (proc.stderr or "") if 32 <= ord(c) < 127)
        return (False, f"gpg verification failed: {cleaned.strip()[:200]}")
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
        return (False, f"gpg invocation failed: {e}")


def filter_verified(templates_dir: Path, template_paths: list[Path]) -> tuple[list[Path], list[Path]]:
    """Split paths into (verified, tampered_or_unsigned).

    When no manifest exists: every template is treated as unverified but
    allowed (legacy mode). When the manifest exists, files NOT in the manifest
    OR with mismatched hashes are placed in the 'tampered' bucket."""
    manifest = load_manifest(templates_dir)
    if not manifest:
        return (list(template_paths), [])
    verified: list[Path] = []
    tampered: list[Path] = []
    for p in template_paths:
        rel = p.name
        if rel not in manifest:
            tampered.append(p)
            continue
        try:
            data = p.read_bytes()
        except OSError:
            tampered.append(p)
            continue
        h = hashlib.sha256(data).hexdigest()
        if h.lower() == manifest[rel]:
            verified.append(p)
        else:
            tampered.append(p)
    return (verified, tampered)
