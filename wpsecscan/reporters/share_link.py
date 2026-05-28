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
            # C4-adjacent (v2.7.2) — `.strip()` here was asymmetric
            # with the raw write below. ~0.8% of random 32-byte
            # secrets have a trailing whitespace byte, so first-call
            # (write+return raw) and second-call (read+strip) returned
            # different secrets, intermittently breaking share-link
            # signatures. Read raw bytes; the file is always exactly
            # 32 bytes long.
            return p.read_bytes()
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


# C4 (v2.7.2) — share-link TTL. The signed payload had no issued_at,
# no expires_at, no nonce; once signed it was valid forever and there
# was no revocation. Now: payload carries issued_at + expires_at (30
# days default), both signed; verify() rejects anything past expiry.
_SHARE_DEFAULT_TTL_S = 30 * 24 * 3600


def build_share_payload(report: ScanReport, check_id: str, index: int,
                          *, ttl_seconds: int = _SHARE_DEFAULT_TTL_S) -> dict[str, Any]:
    """Build the JSON-LD payload for one finding."""
    from .. import __version__
    import time as _time

    target_check = next((r for r in report.results if r.check_id == check_id), None)
    if not target_check:
        raise ValueError(f"check_id {check_id!r} not in report")
    if index < 0 or index >= len(target_check.findings):
        raise ValueError(f"index {index} out of range for {check_id} (has {len(target_check.findings)})")

    finding = target_check.findings[index]
    now = int(_time.time())
    payload = {
        "@context": "https://wpsecscan.dev/share/v1",
        "@type": "Finding",
        "target": report.target,
        "scanned_at": report.scanned_at,
        "check_id": check_id,
        "check_name": target_check.check_name,
        "finding": finding.to_dict(),
        "scanner_version": __version__,
        # C4 — both fields are inside the signed body so they can't be
        # forward-dated by a recipient.
        "issued_at": now,
        "expires_at": now + max(60, int(ttl_seconds)),
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
    """Verify the HMAC signature on a share-link payload AND that the
    `expires_at` field hasn't lapsed. Both checks are required:
    signature alone (per v2.7.1) was forgery-proof but never revoked."""
    import time as _time

    if "signature" not in share_payload:
        return False
    sig = share_payload["signature"]
    body = {k: v for k, v in share_payload.items()
             if k not in ("signature", "share_id")}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(_share_secret(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    # C4 (v2.7.2) — TTL enforcement. Old payloads (pre-v2.7.2) won't
    # have expires_at; treat that as "expired" so a leaked old link
    # can't be replayed forever once the recipient upgrades.
    try:
        expires_at = int(body.get("expires_at", 0))
    except (TypeError, ValueError):
        return False
    if expires_at <= 0:
        return False
    return _time.time() < expires_at
