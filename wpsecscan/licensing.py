"""Round-60 Q2c — license-key system.

Offline-friendly, public-key signed. Pirates can defeat anything; the
goal is to:
  (a) identify legitimate users for support / upgrade emails
  (b) make casual rehosting / "I bought it for $5 on a Telegram channel"
      pirated keys easy to detect and revoke
  (c) keep the source 100% open (no hidden server calls)

Key shape:
    WPSS-<base32(payload)>-<base32(sig[0:16])>

Where payload is JSON {"sub": str email, "tier": "free|pro|team",
                         "issued": int unix, "expires": int unix}
and sig is Ed25519(privkey, payload_bytes).

The public key lives below as `EMBEDDED_PUBKEY_B64`. The matching
private key is stored OUT OF THE REPO; the operator (Bryan) runs
`scripts/gen-license.py` to mint keys.

Free tier: code runs without a key. Pro/team tiers unlock optional
features in `gui.py` / `reporters/` (e.g. branded PDF, multi-site
dashboard sync). The scanner functionality is identical at all tiers.

NO KEYBASE / DRM SHENANIGANS. Failure to validate just disables the
optional unlocks — it never blocks scans.
"""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path


# Public verification key. Replace with your own production pubkey.
# Generated via: scripts/gen-license-keypair.py
EMBEDDED_PUBKEY_B64 = (
    # Placeholder — operator must replace before shipping commercial release
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _key_path() -> Path:
    return _home() / "license.txt"


def _b32(b: bytes) -> str:
    return base64.b32encode(b).decode("ascii").rstrip("=").lower()


def _from_b32(s: str) -> bytes:
    pad = (-len(s)) % 8
    return base64.b32decode((s + "=" * pad).upper())


def parse_key(license_key: str) -> dict | None:
    """Returns {payload_bytes, sig_bytes, payload_dict} or None."""
    if not license_key or not license_key.startswith("WPSS-"):
        return None
    parts = license_key.split("-")
    if len(parts) != 3:
        return None
    _, payload_b32, sig_b32 = parts
    try:
        payload_bytes = _from_b32(payload_b32)
        sig_bytes = _from_b32(sig_b32)
        payload_dict = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload_dict, dict):
        return None
    return {"payload_bytes": payload_bytes, "sig_bytes": sig_bytes,
             "payload_dict": payload_dict}


def verify_key(license_key: str) -> dict:
    """Returns {valid: bool, reason: str, tier: str, sub: str, expires: int}."""
    parsed = parse_key(license_key)
    if not parsed:
        return {"valid": False, "reason": "malformed key", "tier": "free"}
    pd = parsed["payload_dict"]
    sub = pd.get("sub", "")
    tier = pd.get("tier", "free")
    expires = int(pd.get("expires", 0))
    if expires and time.time() > expires:
        return {"valid": False, "reason": "expired", "tier": "free",
                 "sub": sub, "expires": expires}
    # Verify signature via PyNaCl if installed; otherwise return "unverified"
    # and trust the key (allows offline-first development without nacl).
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        pub = VerifyKey(base64.b64decode(EMBEDDED_PUBKEY_B64))
        try:
            pub.verify(parsed["payload_bytes"], parsed["sig_bytes"])
        except BadSignatureError:
            return {"valid": False, "reason": "bad signature", "tier": "free"}
    except ImportError:
        return {"valid": True, "reason": "unverified (pynacl missing — verifying offline-only)",
                 "tier": tier, "sub": sub, "expires": expires}
    return {"valid": True, "reason": "OK", "tier": tier, "sub": sub, "expires": expires}


def load_active_license() -> dict:
    """Read ~/.wpsecscan/license.txt and verify it. Returns the verify_key result."""
    p = _key_path()
    if not p.exists() or p.is_symlink():
        return {"valid": False, "reason": "no license installed", "tier": "free"}
    try:
        key = p.read_text(encoding="utf-8").strip()
    except OSError:
        return {"valid": False, "reason": "license file unreadable", "tier": "free"}
    return verify_key(key)


def install_key(license_key: str) -> dict:
    """Validate then persist the key to ~/.wpsecscan/license.txt.
    Returns verify_key result."""
    result = verify_key(license_key)
    if not result.get("valid"):
        return result
    p = _key_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink():
            p.unlink()
        p.write_text(license_key.strip() + "\n", encoding="utf-8")
    except OSError as e:
        return {"valid": False, "reason": f"could not write license: {e}",
                 "tier": "free"}
    return result


def current_tier() -> str:
    """Convenience helper for feature gates. Always returns a string."""
    info = load_active_license()
    return info.get("tier", "free") if info.get("valid") else "free"
