"""Signed-webhook v2 — HMAC + nonce + replay window.

Round-64 #146 — webhook v1 was just an HMAC over the body. v2 adds:
  - X-Wpsec-Nonce: random per-delivery; receiver remembers last N to
    reject replays
  - X-Wpsec-Timestamp: receiver rejects deliveries older than 5 min
  - X-Wpsec-Signature: HMAC over `timestamp.nonce.body`
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import deque
from dataclasses import dataclass


REPLAY_WINDOW_SECONDS = 300  # 5 min
NONCE_CACHE_SIZE = 4096


@dataclass
class SignedWebhook:
    timestamp: int
    nonce: str
    signature: str
    body: bytes

    @classmethod
    def sign(cls, body: bytes, secret: str) -> "SignedWebhook":
        ts = int(time.time())
        nonce = secrets.token_urlsafe(16)
        signed = f"{ts}.{nonce}.".encode("ascii") + body
        sig = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
        return cls(timestamp=ts, nonce=nonce, signature=sig, body=body)

    def headers(self) -> dict[str, str]:
        return {
            "X-Wpsec-Timestamp": str(self.timestamp),
            "X-Wpsec-Nonce":     self.nonce,
            "X-Wpsec-Signature": self.signature,
            "Content-Type":      "application/json",
        }


class WebhookVerifier:
    """Stateful — keep one instance per receiver to track replays."""

    def __init__(self, secret: str, *, replay_window: int = REPLAY_WINDOW_SECONDS) -> None:
        self._secret = secret.encode("utf-8")
        self._replay_window = replay_window
        self._seen_nonces: deque[str] = deque(maxlen=NONCE_CACHE_SIZE)
        self._seen_nonce_set: set[str] = set()

    def verify(self, body: bytes, headers: dict[str, str]) -> bool:
        ts_hdr = headers.get("X-Wpsec-Timestamp") or headers.get("x-wpsec-timestamp")
        nonce = headers.get("X-Wpsec-Nonce") or headers.get("x-wpsec-nonce")
        sig = headers.get("X-Wpsec-Signature") or headers.get("x-wpsec-signature")
        if not ts_hdr or not nonce or not sig:
            return False
        try:
            ts = int(ts_hdr)
        except ValueError:
            return False
        # Replay-window check
        if abs(time.time() - ts) > self._replay_window:
            return False
        # Nonce replay check
        if nonce in self._seen_nonce_set:
            return False
        # Signature check
        signed = f"{ts}.{nonce}.".encode("ascii") + body
        expected = hmac.new(self._secret, signed, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False
        # Accept + remember the nonce
        if len(self._seen_nonces) == self._seen_nonces.maxlen:
            evicted = self._seen_nonces[0]
            self._seen_nonce_set.discard(evicted)
        self._seen_nonces.append(nonce)
        self._seen_nonce_set.add(nonce)
        return True


def build_signed_request(payload: dict, secret: str) -> tuple[dict, str]:
    """Returns (headers, body_string) suitable for httpx.post(..., headers=h, content=body)."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sw = SignedWebhook.sign(body, secret)
    return sw.headers(), body.decode("utf-8")
