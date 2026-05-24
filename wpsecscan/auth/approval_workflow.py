"""Two-person sign-off for aggressive scans.

Round-64 #118 — for compliance shops (financial, healthcare, gov) that
mandate two approvers on any destructive-class scan. The first user
creates an `ApprovalRequest`; the second approves before the scan can
run.

Request state stored at `~/.wpsecscan/approvals/<id>.json`.
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def _store_dir() -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    return home / "approvals"


@dataclass
class ApprovalRequest:
    request_id: str
    requested_by: str
    target: str
    action: str
    reason: str
    created_at: str
    approved_by: str | None = None
    approved_at: str | None = None
    expires_at: str | None = None
    consumed: bool = False  # set once the scan has run, prevents reuse

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict) -> "ApprovalRequest":
        return cls(**{k: d.get(k) for k in cls.__dataclass_fields__})


def create_request(requested_by: str, target: str, action: str, reason: str, ttl_seconds: int = 3600) -> ApprovalRequest:
    rid = secrets.token_urlsafe(12)
    now = datetime.now(tz=timezone.utc)
    expires = now.timestamp() + ttl_seconds
    req = ApprovalRequest(
        request_id=rid,
        requested_by=requested_by,
        target=target,
        action=action,
        reason=reason,
        created_at=now.isoformat(),
        expires_at=datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(),
    )
    _save(req)
    return req


def approve(request_id: str, approver: str) -> ApprovalRequest:
    req = _load(request_id)
    if req.consumed:
        raise ValueError("Request has already been used")
    if req.approved_by:
        raise ValueError("Already approved")
    if approver == req.requested_by:
        raise ValueError("Approver and requester must be different (two-person rule)")
    req.approved_by = approver
    req.approved_at = datetime.now(tz=timezone.utc).isoformat()
    _save(req)
    return req


def consume(request_id: str) -> ApprovalRequest:
    """Mark approved + used. Call right before running the scan."""
    req = _load(request_id)
    if not req.approved_by:
        raise PermissionError("Not approved")
    # Expiry check
    if req.expires_at:
        try:
            exp_ts = datetime.fromisoformat(req.expires_at).timestamp()
            if datetime.now(tz=timezone.utc).timestamp() > exp_ts:
                raise PermissionError("Approval expired")
        except ValueError:
            pass
    req.consumed = True
    _save(req)
    return req


def _save(req: ApprovalRequest) -> None:
    d = _store_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{req.request_id}.json"
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps(req.to_dict(), indent=2), encoding="utf-8")


def _load(request_id: str) -> ApprovalRequest:
    p = _store_dir() / f"{request_id}.json"
    if not p.exists():
        raise KeyError(f"Approval request {request_id} not found")
    return ApprovalRequest.from_dict(json.loads(p.read_text(encoding="utf-8")))
