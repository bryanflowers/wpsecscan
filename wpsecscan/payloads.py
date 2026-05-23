"""Curated read-only payload library — backs the Payload Tester GUI.

Loads payloads.json, enforces read_only=true at load time, exposes
filter/dispatch helpers. The detection shape mirrors exploit_signatures.json
so the same "match"/"match_value" interpreters can be reused.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

VALID_CATEGORIES = ("sqli", "xss", "lfi", "ssrf", "open_redirect", "header_injection")
VALID_RISKS = ("low", "medium", "high")
VALID_MATCH = ("status_eq", "status_in", "body_contains", "header_contains", "sleep_delta", "length_delta")


def _data_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data"
    return Path(__file__).resolve().parent / "data"


@dataclass
class Payload:
    id: str
    category: str
    title: str
    description: str
    payload: str
    risk: str
    read_only: bool
    detect: dict
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "category": self.category, "title": self.title,
            "description": self.description, "payload": self.payload,
            "risk": self.risk, "read_only": self.read_only,
            "detect": self.detect, "tags": self.tags,
        }


def load_payloads() -> list[Payload]:
    """Load + validate payloads.json. Raises ValueError on any invariant violation.

    F4: also merges any user-supplied custom payloads from
    `~/.wpsecscan/payloads/*.json`. Each file may be a list of payload dicts OR
    `{"payloads": [...]}`. Custom payloads MUST still pass the read_only=true
    invariant — anything trying to ship a write-side payload via the drop-in
    directory is rejected with the same error as the built-in file.
    """
    f = _data_dir() / "payloads.json"
    if not f.exists():
        raise FileNotFoundError(f"payloads.json not found at {f}")
    data = json.loads(f.read_text(encoding="utf-8"))
    raw = list(data.get("payloads") or [])
    # F4: merge user custom payloads
    try:
        import os
        from pathlib import Path as _P
        home = os.environ.get("WPSECSCAN_HOME") or (_P.home() / ".wpsecscan")
        pl_dir = _P(home) / "payloads"
        if pl_dir.exists():
            for pf in sorted(pl_dir.glob("*.json")):
                try:
                    blob = json.loads(pf.read_text(encoding="utf-8"))
                    if isinstance(blob, list):
                        raw.extend(blob)
                    elif isinstance(blob, dict):
                        raw.extend(blob.get("payloads") or [])
                except (OSError, json.JSONDecodeError):
                    continue
    except Exception:  # noqa: BLE001
        pass
    out: list[Payload] = []
    seen_ids: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"payloads[{i}] is not an object")
        pid = item.get("id")
        if not pid or pid in seen_ids:
            raise ValueError(f"payloads[{i}] has duplicate or missing id: {pid!r}")
        seen_ids.add(pid)
        if item.get("category") not in VALID_CATEGORIES:
            raise ValueError(f"payloads[{pid}] invalid category: {item.get('category')!r}")
        if item.get("risk") not in VALID_RISKS:
            raise ValueError(f"payloads[{pid}] invalid risk: {item.get('risk')!r}")
        # Non-negotiable: every payload must be marked read-only.
        if item.get("read_only") is not True:
            raise ValueError(f"payloads[{pid}] is not marked read_only=true")
        det = item.get("detect") or {}
        if det.get("match") not in VALID_MATCH:
            raise ValueError(f"payloads[{pid}] invalid detect.match: {det.get('match')!r}")
        out.append(Payload(
            id=pid,
            category=item["category"],
            title=item.get("title") or pid,
            description=item.get("description") or "",
            payload=item["payload"],
            risk=item["risk"],
            read_only=True,
            detect=det,
            tags=list(item.get("tags") or []),
        ))
    return out


def by_category(payloads: list[Payload], category: str) -> list[Payload]:
    return [p for p in payloads if p.category == category]


def evaluate_response(payload: Payload, status_code: int, body: str, headers: dict,
                      duration_seconds: float, baseline_length: int | None = None) -> tuple[bool, str]:
    """Apply the payload's detect rule against a real response.
    Returns (triggered, human-readable detail)."""
    det = payload.detect
    kind = det.get("match")
    val = det.get("match_value")

    if kind == "status_eq":
        ok = (status_code == val)
        return ok, f"HTTP {status_code} (expected {val})"
    if kind == "status_in":
        ok = status_code in (val or [])
        return ok, f"HTTP {status_code} (expected one of {val})"
    if kind == "body_contains":
        ok = bool(isinstance(val, str) and val.lower() in (body or "").lower())
        return ok, f"HTTP {status_code}; body contains {val!r}: {ok}"
    if kind == "header_contains":
        # match_value is a "Header-Name: substring" string
        if isinstance(val, str):
            for hk, hv in (headers or {}).items():
                line = f"{hk}: {hv}".lower()
                if val.lower() in line:
                    return True, f"matched header line: {hk}: {hv[:80]}"
        return False, f"no header matched {val!r}"
    if kind == "sleep_delta":
        threshold = float(val or 2.5)
        ok = duration_seconds >= threshold
        return ok, f"duration {duration_seconds*1000:.0f} ms (threshold {threshold*1000:.0f} ms)"
    if kind == "length_delta":
        if baseline_length is None or baseline_length == 0:
            return False, "no baseline available"
        delta = abs(len(body or "") - baseline_length) / max(baseline_length, 1)
        threshold = float(val or 0.15)
        ok = delta >= threshold
        return ok, f"length delta {delta:.0%} (threshold {threshold:.0%})"
    return False, f"unknown match kind: {kind}"
