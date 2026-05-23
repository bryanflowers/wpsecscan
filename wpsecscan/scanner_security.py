"""#109-114 Scanner-itself security hardening.

#109 encrypted-at-rest reports — `--encrypt-with <gpg-key>`
#110 secure-erase — `--shred-older-than 90d`
#111 sandboxed plugin execution — run user Python plugins in a separate
     process with restricted env
#112 SBOM signed with Sigstore — wrapper around the sigstore CLI
#113 SLSA Level 3+ provenance — documented build attestation steps
#114 permissions audit — flag world-readable ~/.wpsecscan/*.json
"""
from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
import time
from pathlib import Path


# ---- #109 encrypt-at-rest ----

def encrypt_file(in_path: Path, gpg_recipient: str, out_path: Path | None = None) -> Path | None:
    """gpg-encrypt `in_path` to `out_path` (default: in_path.gpg). Requires gpg on PATH."""
    if not shutil.which("gpg"):
        return None
    out = out_path or in_path.with_suffix(in_path.suffix + ".gpg")
    try:
        subprocess.run(["gpg", "--yes", "--batch", "--encrypt",
                        "--recipient", gpg_recipient, "--output", str(out), str(in_path)],
                       capture_output=True, check=True, timeout=30)
        return out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None


# ---- #110 secure-erase ----

def shred_older_than(directory: Path, days: int, *, dry_run: bool = False) -> list[Path]:
    """Cryptographically wipe files in `directory` older than N days.
    Returns the list of files affected. Uses random-byte overwrite + unlink."""
    if not directory.exists():
        return []
    cutoff = time.time() - days * 86400
    wiped: list[Path] = []
    for p in directory.rglob("*"):
        # Skip symlinks BEFORE is_file (which follows them) so an attacker
        # can't plant a symlink in the shred dir pointing at /etc/passwd.
        if p.is_symlink():
            continue
        if not p.is_file():
            continue
        try:
            if p.stat().st_mtime > cutoff:
                continue
            wiped.append(p)
            if dry_run:
                continue
            # 3-pass random overwrite
            size = p.stat().st_size
            with p.open("rb+") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
            p.unlink()
        except OSError:
            continue
    return wiped


# ---- #111 sandboxed plugin execution ----

def run_plugin_sandboxed(plugin_path: Path, input_json: str, *, timeout: float = 10.0) -> str:
    """Run a Python plugin as a subprocess with restricted env.

    Limitations: not a true sandbox (no chroot, no seccomp on Windows). What
    it DOES provide: separate process so a crash doesn't kill the scanner,
    truncated env so the plugin can't read scanner secrets, timeout.
    """
    safe_env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "PYTHONIOENCODING": "utf-8",
    }
    try:
        proc = subprocess.run(
            ["python", str(plugin_path)],
            input=input_json, capture_output=True, text=True,
            env=safe_env, timeout=timeout,
        )
        return proc.stdout or ""
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return ""


# ---- #112 sigstore signing ----

def sigstore_sign_release(artifact: Path) -> Path | None:
    """Use `cosign sign-blob` if available. Returns the .sigstore bundle path."""
    if not shutil.which("cosign"):
        return None
    out = artifact.with_suffix(artifact.suffix + ".sigstore")
    try:
        subprocess.run(
            ["cosign", "sign-blob", "--yes", "--bundle", str(out), str(artifact)],
            capture_output=True, check=True, timeout=60,
        )
        return out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None


# ---- #114 permissions audit ----

def audit_permissions() -> list[dict]:
    """Walk ~/.wpsecscan; flag any file with world-readable bits or any
    sensitive-named file that's group-readable. Returns list of issues."""
    from . import history as _h
    home = Path(_h._home())
    issues: list[dict] = []
    if not home.exists():
        return issues
    sensitive_names = {"users.json", "settings.json", "audit.log.jsonl",
                       "contexts", "alert_filters.json", "marketplace_cache.json"}
    for p in home.rglob("*"):
        if not p.is_file():
            continue
        try:
            mode = p.stat().st_mode
        except OSError:
            continue
        is_sensitive = p.name in sensitive_names or "contexts" in p.parts
        # On POSIX, check world-read bit
        if hasattr(stat, "S_IROTH") and (mode & stat.S_IROTH):
            issues.append({"path": str(p), "mode_octal": oct(mode & 0o777),
                           "issue": "world-readable"})
        if is_sensitive and hasattr(stat, "S_IRGRP") and (mode & stat.S_IRGRP):
            issues.append({"path": str(p), "mode_octal": oct(mode & 0o777),
                           "issue": "sensitive file is group-readable"})
    return issues
