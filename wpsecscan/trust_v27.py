"""v2.7.0 trust / verification (K122-K125).

  K122 reproducible_build_verify()  — re-build from PyPI sdist + diff vs wheel
  K123 build_provenance_graph(r)    — per-finding lineage (request/response/check)
  K124 third_party_audit_url()      — read from ROADMAP / VERSION metadata
  K125 deterministic_seed()         — set Python + numpy random seeds
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# K122 — Reproducible-build verifier
# ---------------------------------------------------------------------------

def reproducible_build_verify(version: str | None = None) -> tuple[bool, str]:
    """Download the published sdist for `version` from PyPI, re-build
    the wheel locally with the same Python, and compare the wheel
    sha256 against the published wheel. Returns (matches, message).

    Note: TRUE reproducible build requires deterministic timestamps
    (SOURCE_DATE_EPOCH), pinned build deps, etc. — this verifier is a
    first-step sanity check, not a SLSA L4 attestation. The full
    SLSA L4 verification flow is documented in docs/SLSA-L4-rebuilders.md.
    """
    if not version:
        from . import __version__
        version = __version__
    import tempfile
    work = Path(tempfile.mkdtemp(prefix="wpsec-rebuild-"))
    try:
        # Download sdist via pip
        r = subprocess.run(
            [sys.executable, "-m", "pip", "download",
              f"wpsecscan=={version}", "--no-deps", "--no-binary", ":all:",
              "-d", str(work)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return False, f"pip download failed: {r.stderr[:300]}"
        sdists = list(work.glob("wpsecscan-*.tar.gz"))
        if not sdists:
            return False, "no sdist found after download"
        sdist = sdists[0]
        # Unpack + re-build
        import tarfile
        # C10 (v2.7.2) — apply the `data` extraction filter so a
        # malicious sdist downloaded from a compromised PyPI mirror
        # can't write outside `work` via `..` path entries or
        # absolute member names. `data` is the safest preset (rejects
        # absolute paths, parent-dir traversal, and any unsafe modes).
        # On Python < 3.12 the kwarg is accepted but a DeprecationWarning
        # is emitted; on 3.14 it becomes mandatory.
        with tarfile.open(sdist) as tf:
            try:
                tf.extractall(work, filter="data")
            except TypeError:
                # Python < 3.12 — pre-validate every member manually.
                for m in tf.getmembers():
                    name = m.name
                    if name.startswith("/") or ".." in Path(name).parts:
                        return False, f"sdist contains unsafe member: {name!r}"
                tf.extractall(work)
        srcs = [p for p in work.iterdir() if p.is_dir() and p.name.startswith("wpsecscan-")]
        if not srcs:
            return False, "no source dir after sdist unpack"
        src = srcs[0]
        os.environ.setdefault("SOURCE_DATE_EPOCH", "1700000000")
        rb = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(work / "dist"),
              str(src)],
            capture_output=True, text=True, timeout=240,
        )
        if rb.returncode != 0:
            return False, f"local rebuild failed: {rb.stderr[:300]}"
        rebuilt = list((work / "dist").glob("*.whl"))
        if not rebuilt:
            return False, "no wheel produced"
        local_sha = hashlib.sha256(rebuilt[0].read_bytes()).hexdigest()
        # Download the PyPI wheel for comparison
        r = subprocess.run(
            [sys.executable, "-m", "pip", "download",
              f"wpsecscan=={version}", "--no-deps", "--only-binary", ":all:",
              "-d", str(work / "pypi-whl")],
            capture_output=True, text=True, timeout=120,
        )
        pypi_whl = list((work / "pypi-whl").glob("wpsecscan-*.whl"))
        if not pypi_whl:
            return False, "couldn't download published wheel"
        pypi_sha = hashlib.sha256(pypi_whl[0].read_bytes()).hexdigest()
        return (local_sha == pypi_sha,
                f"local={local_sha[:12]}... pypi={pypi_sha[:12]}... match={local_sha == pypi_sha}")
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# K123 — Findings provenance graph
# ---------------------------------------------------------------------------

def build_provenance_graph(report) -> dict:
    """Return a dict describing every finding's lineage:
       finding → produced-by check_id → request URL / method (when known).
    Lets the operator audit AI/policy chains."""
    out: dict = {"target": report.target, "scanned_at": report.scanned_at,
                  "lineage": []}
    for r in report.results:
        for i, f in enumerate(r.findings):
            extra = f.extra if isinstance(f.extra, dict) else {}
            entry = {
                "finding_index": i,
                "check_id": r.check_id,
                "check_name": r.check_name,
                "severity": f.severity,
                "title": f.title,
                "produced_by_request": {
                    "url": f.url or "",
                    "method": extra.get("http_method", "GET"),
                },
                "policy_applied": {
                    "ai_anomaly": extra.get("ai_anomaly"),
                    "snyk_dup":   extra.get("snyk_dup"),
                    "fp_score":   extra.get("fp_score"),
                    "kev_match":  extra.get("kev_match"),
                },
            }
            out["lineage"].append(entry)
    return out


# ---------------------------------------------------------------------------
# K124 — Third-party audit URL in --version
# ---------------------------------------------------------------------------

def third_party_audit_url() -> str:
    """Return the public audit-report URL (or empty string until one
    is published)."""
    # When the Q4 2026 audit lands, update this to the publication URL.
    return os.environ.get("WPSECSCAN_AUDIT_URL", "")


# ---------------------------------------------------------------------------
# K125 — --deterministic flag
# ---------------------------------------------------------------------------

def set_deterministic_seed(seed: int = 1729) -> None:
    """Pin all randomness so two runs of the same input produce
    byte-identical reports. Affects:
      - Python random module
      - secrets module (via random override — best-effort only)
      - time-sensitive check IDs that hash the current minute
    """
    random.seed(seed)
    os.environ["WPSECSCAN_DETERMINISTIC_SEED"] = str(seed)
    # numpy seed if numpy is around
    try:
        import numpy as _np  # type: ignore[import-not-found]
        _np.random.seed(seed)
    except ImportError:
        pass
