"""JWT audit — decode + test weak HS256 secret + `alg=none` acceptance.

Walks the response Set-Cookie + body for JWT-shaped tokens (three dot-separated
base64url segments). For each token:
  1. Decode header + claims (no signature verification).
  2. Flag `alg=none` tokens (server allows unsigned tokens = full impersonation).
  3. Brute-force a TINY top-50 list of common HS256 secrets — if any matches,
     the server signed with a known-weak secret (`secret`, `password`, etc).
  4. Build a tampered `alg=none` token and POST it back to detect server-side
     `alg=none` acceptance.

Aggressive-only (sends a tampered token).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json as _json
import re

from ..http import Client
from ..models import Finding

# Top-50 JWT secret guesses (from jwt.secrets.list, capped to keep scan fast).
COMMON_HS256_SECRETS = (
    "", "secret", "password", "1234567890", "key", "jwt", "hs256",
    "test", "abc123", "letmein", "admin", "default", "qwerty",
    "your-256-bit-secret", "your_jwt_secret", "supersecret",
    "secretkey", "topsecret", "jwt-secret", "jwt_secret",
    "wpsecret", "wordpress", "wp_secret", "demo", "example",
    "hello", "world", "changeme", "iloveyou", "Welcome",
    "Password1", "passwd", "root", "toor", "admin123",
    "12345678", "abcd1234", "secret123", "MySecretKey",
    "jwt_password", "secret_key", "private_key",
    "your-256-bit-secret-keep-it-safe", "0", "null",
    "JsonWebToken", "Bearer", "auth", "token", "session",
)

JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _decode_jwt(token: str) -> tuple[dict, dict] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = _json.loads(_b64url_decode(parts[0]))
        claims = _json.loads(_b64url_decode(parts[1]))
        return header, claims
    except (ValueError, _json.JSONDecodeError, UnicodeDecodeError):
        return None


def _try_hs256_secret(token: str, secret: str) -> bool:
    """Return True if `secret` correctly signs this HS256 token."""
    try:
        header_b64, claims_b64, sig_b64 = token.split(".")
        msg = (header_b64 + "." + claims_b64).encode("ascii")
        expected = _b64url_encode(hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest())
        return hmac.compare_digest(expected, sig_b64)
    except (ValueError, TypeError):
        return False


def _build_alg_none(token: str) -> str:
    """Tamper a JWT to use alg=none with the original claims."""
    try:
        _hdr_b64, claims_b64, _sig = token.split(".")
        header = {"alg": "none", "typ": "JWT"}
        header_b64 = _b64url_encode(_json.dumps(header, separators=(",", ":")).encode("utf-8"))
        return f"{header_b64}.{claims_b64}."
    except ValueError:
        return ""


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # Collect JWTs from a few candidate pages
    tokens: set[str] = set()
    for path in ("/", "/wp-login.php", "/wp-json/", "/wp-admin/admin-ajax.php"):
        step(f"scanning {path} for JWTs...")
        r = await client.get(path)
        if r is None:
            continue
        body = (r.text or "")[:60000]
        for m in JWT_PATTERN.findall(body):
            tokens.add(m)
        # Set-Cookie headers
        if hasattr(r.headers, "get_list"):
            for v in r.headers.get_list("set-cookie"):
                for m in JWT_PATTERN.findall(v):
                    tokens.add(m)

    if not tokens:
        findings.append(
            Finding(
                severity="info",
                title="No JWTs detected on probed pages",
                evidence="Scanned / wp-login.php /wp-json/ /wp-admin/admin-ajax.php for JWT-shaped tokens.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    aggressive = bool(ctx.get("aggressive"))
    for token in list(tokens)[:5]:  # cap at 5 tokens per scan
        step(f"analysing JWT (first 40 chars: {token[:40]}...)")
        decoded = _decode_jwt(token)
        if not decoded:
            continue
        header, claims = decoded
        alg = (header.get("alg") or "").lower()

        # 1) alg=none in a real token = critical
        if alg == "none":
            findings.append(
                Finding(
                    severity="critical",
                    title="JWT issued with `alg=none` — unsigned token in use",
                    evidence=(
                        f"Header: {header}\n"
                        f"Claims: {claims}\n"
                        "An unsigned JWT means the server accepts ANY claims at face value. Anyone can mint a token "
                        "with `sub: admin` and gain access."
                    ),
                    remediation=(
                        "Configure the JWT library to require RS256 or ES256. Reject `alg=none` at validation. "
                        "WP JWT Auth plugins should NEVER allow this; if yours does, switch plugins."
                    ),
                    url=ctx["target"],
                    extra={"jwt_header": header, "jwt_claims": claims},
                )
            )

        # 2) HS256 weak-secret brute force
        if alg == "hs256":
            cracked = None
            for secret in COMMON_HS256_SECRETS:
                if _try_hs256_secret(token, secret):
                    cracked = secret
                    break
            if cracked is not None:
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"JWT signed with weak HS256 secret: {cracked!r}",
                        evidence=(
                            f"Token header: {header}\n"
                            f"Claims: {claims}\n"
                            f"HMAC-SHA256 secret was guessed from the top-50 list.\n"
                            "An attacker can forge JWTs for any user."
                        ),
                        remediation=(
                            "Rotate the JWT signing secret immediately. Use a 256-bit random key "
                            "(`openssl rand -hex 32`). Better: switch to RS256/ES256 with an asymmetric key."
                        ),
                        url=ctx["target"],
                        # The cracked secret value is already in the finding title; persisting
                        # it a second time in `extra` would multiply copies of a leaked credential
                        # in archived JSON reports.
                        extra={"jwt_header": header, "jwt_claims": claims},
                    )
                )

        # 3) Active `alg=none` acceptance test (aggressive only)
        if aggressive and alg in ("hs256", "rs256", "es256"):
            tampered = _build_alg_none(token)
            if tampered:
                step("testing server `alg=none` acceptance...")
                # Try the tampered token as a Bearer + as a cookie. We send to a known
                # WP REST endpoint that's likely auth-gated.
                r = await client.get("/wp-json/wp/v2/users/me",
                                      headers={"Authorization": f"Bearer {tampered}"})
                if r is not None and r.status_code == 200 and "id" in (r.text or ""):
                    findings.append(
                        Finding(
                            severity="critical",
                            title="Server accepts `alg=none` JWT — full auth bypass",
                            evidence=(
                                f"Sent a tampered token with `alg=none` to /wp-json/wp/v2/users/me; "
                                f"got HTTP 200 with what looks like a user object.\n\n"
                                f"Original claims (re-used in the tampered token): {claims}"
                            ),
                            remediation=(
                                "Disable `alg=none` acceptance. The JWT library is probably "
                                "`firebase/php-jwt` or `lcobucci/jwt`; both have a `setAllowedAlgs()` "
                                "method — set it to ['HS256','RS256','ES256'] EXPLICITLY."
                            ),
                            url=client.url("/wp-json/wp/v2/users/me"),
                            extra={"tampered_token": tampered[:80] + "..."},
                        )
                    )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title=f"Found {len(tokens)} JWT(s); all use signed algorithms with non-trivial secrets",
                evidence=f"Tokens: {len(tokens)}; weak-secret + alg=none checks all clean.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
    return findings
