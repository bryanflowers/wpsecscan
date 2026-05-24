"""OIDC SSO scaffold for the daemon REST API.

Round-64 #114 — JWT verify against an OIDC provider (Okta, Auth0,
Google Workspace). Use as a FastAPI/Starlette dependency.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import httpx


@dataclass
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str | None = None  # auto-derived from issuer if None
    cache_ttl: int = 3600


class OIDCVerifier:
    """Single-class verifier with a tiny JWKS cache."""

    def __init__(self, config: OIDCConfig) -> None:
        self.config = config
        self._jwks: dict | None = None
        self._jwks_fetched_at: float = 0.0

    async def _fetch_jwks(self) -> dict:
        url = self.config.jwks_url or f"{self.config.issuer.rstrip('/')}/.well-known/jwks.json"
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url)
            r.raise_for_status()
            return r.json()

    async def jwks(self) -> dict:
        now = time.time()
        if self._jwks is None or now - self._jwks_fetched_at > self.config.cache_ttl:
            self._jwks = await self._fetch_jwks()
            self._jwks_fetched_at = now
        return self._jwks

    async def verify(self, token: str) -> dict:
        """Verify + return claims. Raises ValueError on failure.

        Uses PyJWT if available; otherwise raises ImportError with install hint.
        """
        try:
            import jwt  # PyJWT
            from jwt import PyJWKClient
        except ImportError as e:
            raise ImportError("pip install pyjwt[crypto] required for OIDC verification") from e

        jwks_url = self.config.jwks_url or f"{self.config.issuer.rstrip('/')}/.well-known/jwks.json"
        signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "ES256"],
            audience=self.config.audience,
            issuer=self.config.issuer,
        )
        return claims


# Convenience for FastAPI users
async def get_current_user(authorization: str, verifier: OIDCVerifier) -> dict:
    if not authorization.startswith("Bearer "):
        raise ValueError("Bearer token required")
    token = authorization[7:]
    return await verifier.verify(token)
