"""C49 (v2.7.0) — per-finding share-link generator.

Writes a sealed JSON-LD blob for a SINGLE finding so the operator can
hand the contractor a one-finding artefact without exposing the rest
of the scan. The output is signed with HMAC-SHA256 keyed by a per-
install secret (~/.wpsecscan/share-secret) so the contractor can
verify provenance.

Output shape (JSON-LD with WPSecScan-specific @context):

  {
    "@context": "https://wpsecscan.dev/share/v1",
    "@type": "Finding",
    "target": "https://example.com",
    "scanned_at": "...",
    "check_id": "headers",
    "finding": { ... full Finding.to_dict() ... },
    "scanner_version": "2.7.0",
    "share_id": "sha256-prefix-of-payload",
    "signature": "hmac-sha256-of-payload-without-this-field"
  }

CLI: `wpsecscan ... --share-finding CHECK_ID#INDEX` writes
     `<stem>-<check_id>-<index>.share.json` to the output dir.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from ..models import ScanReport


def _secret_path() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    return home / "share-secret"


def _share_secret() -> bytes:
    p = _secret_path()
    if p.exists():
        try:
            return p.read_bytes().strip()
        except OSError:
            pass
    secret = secrets.token_bytes(32)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secret)
    except OSError:
        pass
    return secret


def build_share_payload(report: ScanReport, check_id: str, index: int) -> dict[str, Any]:
    """Build the JSON-LD payload for one finding."""
    from .. import __version__

    target_check = next((r for r in report.results if r.check_id == check_id), None)
    if not target_check:
        raise ValueError(f"check_id {check_id!r} not in report")
    if index < 0 or index >= len(target_check.findings):
        raise ValueError(f"index {index} out of range for {check_id} (has {len(target_check.findings)})")

    finding = target_check.findings[index]
    payload = {
        "@context": "https://wpsecscan.dev/share/v1",
        "@type": "Finding",
        "target": report.target,
        "scanned_at": report.scanned_at,
        "check_id": check_id,
        "check_name": target_check.check_name,
        "finding": finding.to_dict(),
        "scanner_version": __version__,
    }
    # Stable JSON encoding for signing
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_share_secret(), raw, hashlib.sha256).hexdigest()
    payload["share_id"] = hashlib.sha256(raw).hexdigest()[:16]
    payload["signature"] = sig
    return payload


def write(report: ScanReport, check_id: str, index: int, out_path: Path) -> dict:
    """Build + write the share file. Returns the payload dict."""
    payload = build_share_payload(report, check_id, index)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def verify(share_payload: dict[str, Any]) -> bool:
    """Verify the HMAC signature on a share-link payload. Used by a
    contractor / future scanner-version to confirm provenance."""
    if "signature" not in share_payload:
        return False
    sig = share_payload["signature"]
    body = {k: v for k, v in share_payload.items()
             if k not in ("signature", "share_id")}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(_share_secret(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)
