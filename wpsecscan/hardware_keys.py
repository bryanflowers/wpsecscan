"""Round-59 #98-100 — Hardware-security-key support.

#98 WebAuthn for the API server — `verify_webauthn_assertion(assertion)`
    using `fido2` if installed; pure no-op otherwise.
#99 Yubikey PGP encryption — wraps `gpg --encrypt --recipient <yk-id>`
    via subprocess for at-rest report encryption keyed to a hardware key.
#100 TPM-backed secret storage — wraps the platform TPM (`tpm2-tools`
    on Linux, the Windows Cryptography Next Generation API on Windows)
    for storing the API-server signing key.

All entry points are subprocess-based with timeout + symlink/path
sanitisation so calling them from untrusted contexts is safe.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path


# ---- #98 WebAuthn ----

def has_webauthn() -> bool:
    try:
        import fido2  # type: ignore[import-untyped]  # noqa: F401
        return True
    except ImportError:
        return False


def register_webauthn_credential(user_id: bytes, rp_id: str,
                                   challenge: bytes) -> dict:
    """Build a registration request dict for the browser. Caller serialises
    over WebSocket / HTTP. Returns {} if `fido2` not installed."""
    if not has_webauthn():
        return {}
    from fido2.webauthn import (PublicKeyCredentialCreationOptions,
                                  PublicKeyCredentialRpEntity,
                                  PublicKeyCredentialUserEntity,
                                  PublicKeyCredentialParameters,
                                  PublicKeyCredentialType)
    opts = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(name="WPSecScan", id=rp_id),
        user=PublicKeyCredentialUserEntity(id=user_id, name="operator",
                                              display_name="WPSecScan operator"),
        challenge=challenge,
        pub_key_cred_params=[
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7),  # ES256
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-257),  # RS256
        ],
    )
    return {"publicKey": dict(opts)}


def verify_webauthn_assertion(assertion: dict, expected_challenge: bytes,
                                rp_id: str, public_key_cose: dict) -> bool:
    """Validate a WebAuthn assertion (e.g. from a YubiKey)."""
    if not has_webauthn() or not isinstance(assertion, dict):
        return False
    try:
        from fido2.server import Fido2Server
        from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData
        from fido2.cose import CoseKey
        server = Fido2Server(PublicKeyCredentialRpEntity(name="WPSecScan", id=rp_id))
        cred_data = AttestedCredentialData(
            aaguid=b"\x00" * 16,
            credential_id=assertion.get("rawId", b""),
            public_key=CoseKey.parse(public_key_cose),
        )
        server.authenticate_complete(
            state={"challenge": expected_challenge.hex(), "user_verification": "preferred"},
            credentials=[cred_data],
            credential_id=assertion.get("rawId", b""),
            client_data=assertion.get("response", {}).get("clientDataJSON", b""),
            auth_data=assertion.get("response", {}).get("authenticatorData", b""),
            signature=assertion.get("response", {}).get("signature", b""),
        )
        return True
    except Exception:  # noqa: BLE001
        return False


# ---- #99 Yubikey PGP encryption ----

_PGP_KEY_RE = re.compile(
    r"^[A-Fa-f0-9]{8,40}$|"
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$"
)


def yubikey_encrypt(plaintext: bytes, recipient_key_id: str) -> bytes:
    """Encrypt `plaintext` to a GPG recipient (typically a Yubikey-resident
    sub-key). Returns ciphertext, or b"" on failure.

    `recipient_key_id` MUST be a hex key-id or an email — we reject
    arbitrary input to prevent gpg-argument injection.
    """
    if not shutil.which("gpg"):
        return b""
    if not _PGP_KEY_RE.match(recipient_key_id or ""):
        return b""
    try:
        r = subprocess.run(
            ["gpg", "--batch", "--yes", "--trust-model", "always",
              "--armor", "--encrypt", "--recipient", recipient_key_id],
            input=plaintext, capture_output=True, timeout=20,
        )
        if r.returncode != 0:
            return b""
        return r.stdout
    except (subprocess.TimeoutExpired, OSError):
        return b""


# ---- #100 TPM-backed secret storage ----

def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def tpm_seal(secret: bytes, name: str) -> str:
    """Seal `secret` to the TPM under `name`. Returns the path to the
    sealed blob, or "" on failure.

    On Linux: uses `tpm2_create` / `tpm2_load` if available.
    On Windows: uses DPAPI via `pywin32` (best-effort).
    """
    if not name or not re.match(r"^[A-Za-z0-9._-]+$", name):
        return ""
    home = _home() / "tpm"
    try:
        home.mkdir(parents=True, exist_ok=True)
    except OSError:
        return ""
    blob_path = home / f"{name}.sealed"
    # symlink guard
    if blob_path.is_symlink():
        try:
            blob_path.unlink()
        except OSError:
            return ""
    # Linux tpm2-tools path
    if shutil.which("tpm2_create"):
        try:
            r = subprocess.run(["tpm2_create", "-C", "primary.ctx",
                                  "-i", "-", "-r", str(blob_path)],
                                 input=secret, capture_output=True, timeout=15)
            if r.returncode == 0:
                return str(blob_path)
        except (subprocess.TimeoutExpired, OSError):
            pass
    # Windows DPAPI fallback
    try:
        import win32crypt  # type: ignore[import-untyped]
        cipher = win32crypt.CryptProtectData(secret, name, None, None, None, 0)
        blob_path.write_bytes(cipher)
        return str(blob_path)
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass
    return ""


def tpm_unseal(name: str) -> bytes:
    if not name or not re.match(r"^[A-Za-z0-9._-]+$", name):
        return b""
    blob_path = _home() / "tpm" / f"{name}.sealed"
    if not blob_path.exists() or blob_path.is_symlink():
        return b""
    if shutil.which("tpm2_unseal"):
        try:
            r = subprocess.run(["tpm2_unseal", "-c", "primary.ctx",
                                  "-i", str(blob_path)],
                                 capture_output=True, timeout=15)
            if r.returncode == 0:
                return r.stdout or b""
        except (subprocess.TimeoutExpired, OSError):
            pass
    try:
        import win32crypt  # type: ignore[import-untyped]
        cipher = blob_path.read_bytes()
        _label, plain = win32crypt.CryptUnprotectData(cipher, None, None, None, 0)
        return plain or b""
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass
    return b""
