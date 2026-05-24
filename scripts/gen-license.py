"""Mint a single WPSecScan license key.

Operator-only — needs the private key (kept OFFLINE).

Usage:
    pip install pynacl
    export WPSECSCAN_LICENSE_PRIVKEY_B64='...'   # the b64 from gen-license-keypair.py
    python scripts/gen-license.py customer@example.com pro 365

Args:
    1. subject (email)
    2. tier (free|pro|team)
    3. days valid (0 = perpetual)
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: gen-license.py SUBJECT TIER DAYS", file=sys.stderr)
        return 2
    sub, tier, days_s = sys.argv[1], sys.argv[2], sys.argv[3]
    if tier not in ("free", "pro", "team"):
        print("tier must be free|pro|team", file=sys.stderr); return 2
    try:
        days = int(days_s)
    except ValueError:
        print("days must be an integer", file=sys.stderr); return 2
    try:
        from nacl.signing import SigningKey
    except ImportError:
        print("pip install pynacl", file=sys.stderr); return 1
    privkey_b64 = os.environ.get("WPSECSCAN_LICENSE_PRIVKEY_B64", "")
    if not privkey_b64:
        print("Set WPSECSCAN_LICENSE_PRIVKEY_B64 env var (output of gen-license-keypair.py).",
               file=sys.stderr)
        return 1
    sk = SigningKey(base64.b64decode(privkey_b64))
    expires = int(time.time()) + days * 86400 if days else 0
    payload = {"sub": sub, "tier": tier,
                "issued": int(time.time()), "expires": expires}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = sk.sign(payload_bytes).signature[:16]  # truncate to fit key length
    payload_b32 = base64.b32encode(payload_bytes).decode().rstrip("=").lower()
    sig_b32     = base64.b32encode(sig).decode().rstrip("=").lower()
    print(f"WPSS-{payload_b32}-{sig_b32}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
