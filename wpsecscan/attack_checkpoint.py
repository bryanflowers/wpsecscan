"""#35 (from turbo-intruder) — per-attack pause / resume / replay.

Long fuzzing attacks (10k+ requests) benefit from being pausable. This
module persists in-flight attack state to ~/.wpsecscan/attack-state/<id>.json
every N completed requests so a Ctrl+C / crash / network drop can be
resumed without re-firing everything.

State format:

    {
      "attack_id": "my_attack",
      "target": "https://...",
      "started_at": 1700000000,
      "completed_indices": [0, 1, 2, ..., 4523],
      "payload_count": 10000,
      "interesting": [...]  // findings collected so far
    }

`save_state` + `load_state` handle the JSON I/O. The actual integration
with attack_scripts.py is opt-in via `engine.checkpoint=True`.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


def _state_dir() -> Path:
    from . import history as _h
    p = Path(_h._home()) / "attack-state"
    p.mkdir(parents=True, exist_ok=True)
    return p


def state_path(attack_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in attack_id)
    return _state_dir() / f"{safe}.json"


def save_state(attack_id: str, data: dict) -> None:
    p = state_path(attack_id)
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def load_state(attack_id: str) -> dict | None:
    p = state_path(attack_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def clear_state(attack_id: str) -> bool:
    p = state_path(attack_id)
    if not p.exists():
        return False
    try:
        p.unlink()
        return True
    except OSError:
        return False


def list_pausable() -> list[dict]:
    """Return list of {attack_id, progress_pct, started_at} for paused attacks."""
    out = []
    for p in _state_dir().glob("*.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        done = len(d.get("completed_indices") or [])
        total = d.get("payload_count") or done
        pct = int(done / total * 100) if total else 0
        out.append({
            "attack_id": d.get("attack_id", p.stem),
            "progress_pct": pct,
            "started_at": d.get("started_at"),
            "target": d.get("target"),
        })
    return out


class CheckpointedRunner:
    """Drop-in helper for attack scripts. Use like:

        runner = CheckpointedRunner("my_attack", target, total=10000)
        for i in runner.resume_range():
            response = await fire_request(payloads[i])
            runner.mark_done(i)
            if interesting:
                runner.add_finding(...)
        runner.complete()
    """

    SAVE_EVERY = 50

    def __init__(self, attack_id: str, target: str, total: int):
        self.attack_id = attack_id
        self.target = target
        self.total = total
        existing = load_state(attack_id)
        if existing:
            self.completed = set(existing.get("completed_indices") or [])
            self.findings = list(existing.get("interesting") or [])
            self.started_at = existing.get("started_at", time.time())
        else:
            self.completed = set()
            self.findings = []
            self.started_at = time.time()
        self._since_last_save = 0

    def resume_range(self):
        """Yield indices that haven't been completed yet."""
        for i in range(self.total):
            if i not in self.completed:
                yield i

    def mark_done(self, idx: int) -> None:
        self.completed.add(idx)
        self._since_last_save += 1
        if self._since_last_save >= self.SAVE_EVERY:
            self._save()
            self._since_last_save = 0

    def add_finding(self, finding_dict: dict) -> None:
        self.findings.append(finding_dict)

    def _save(self) -> None:
        save_state(self.attack_id, {
            "attack_id": self.attack_id,
            "target": self.target,
            "started_at": self.started_at,
            "completed_indices": sorted(self.completed),
            "payload_count": self.total,
            "interesting": self.findings,
        })

    def complete(self) -> list[dict]:
        """Persist a final snapshot then clear. Returns the findings list."""
        self._save()
        clear_state(self.attack_id)
        return list(self.findings)
