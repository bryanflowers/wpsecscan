"""Generate an Ed25519 keypair for WPSecScan license signing.

Run ONCE per project lifetime. Save the private key OFFLINE — losing it
means you can never mint another valid license. Replace the public key
in `wpsecscan/licensing.py:EMBEDDED_PUBKEY_B64` with the printed output.

Usage:
    pip install pynacl
    python scripts/gen-license-keypair.py
"""
from __future__ import annotations

import base64
import sys


def main() -> int:
    try:
        from nacl.signing import SigningKey
    except ImportError:
        print("pip install pynacl first", file=sys.stderr)
        return 1
    sk = SigningKey.generate()
    vk = sk.verify_key
    print("# Private key (KEEP SECRET — OFFLINE STORAGE ONLY):")
    print(base64.b64encode(bytes(sk)).decode())
    print()
    print("# Public key (paste into wpsecscan/licensing.py EMBEDDED_PUBKEY_B64):")
    print(base64.b64encode(bytes(vk)).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
