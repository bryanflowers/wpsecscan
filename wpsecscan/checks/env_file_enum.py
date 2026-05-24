"""Probe + content-sniff for exposed .env files.

Round-64 #67 — Laravel/Symfony/Node-style .env files keep cropping up in
WordPress docroots (devs working alongside a Laravel API, or just bad
copy-paste habits). These files are usually pure secrets: DB creds,
AWS keys, Stripe keys, JWT secrets. We probe likely paths and, on hit,
scan the body for high-confidence secret patterns.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

_PROBE_PATHS = (
    "/.env",
    "/.env.local",
    "/.env.prod",
    "/.env.production",
    "/.env.dev",
    "/.env.development",
    "/.env.backup",
    "/.env.old",
    "/.env.save",
    "/wp-content/.env",
    "/wp-content/themes/.env",
    "/app/.env",
)

# High-confidence secret patterns. Each must be specific enough that a
# match in a plain-text file is a true positive.
_SECRET_PATTERNS = (
    (re.compile(r"AKIA[0-9A-Z]{16}"),                 "AWS access key ID"),
    (re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}", re.IGNORECASE), "AWS secret key"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}"),       "Stripe LIVE secret key"),
    (re.compile(r"\brk_live_[A-Za-z0-9]{24,}"),       "Stripe LIVE restricted key"),
    (re.compile(r"DATABASE_URL\s*=\s*[a-z]+://[^@\s]+:[^@\s]+@", re.IGNORECASE), "Database URL with embedded credentials"),
    (re.compile(r"DB_PASSWORD\s*=\s*\S{4,}", re.IGNORECASE), "DB_PASSWORD"),
    (re.compile(r"JWT_SECRET\s*=\s*\S{8,}", re.IGNORECASE), "JWT_SECRET"),
    (re.compile(r"SENDGRID_API_KEY\s*=\s*SG\.[A-Za-z0-9_.-]+", re.IGNORECASE), "SendGrid API key"),
    (re.compile(r"MAILGUN_API_KEY\s*=\s*key-[A-Za-z0-9]+", re.IGNORECASE), "Mailgun API key"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----"), "Private key"),
)


def _looks_like_env(body: str) -> bool:
    """Heuristic: at least 2 KEY=VALUE lines."""
    matches = re.findall(r"^[A-Z][A-Z0-9_]+\s*=\s*\S", body, re.MULTILINE)
    return len(matches) >= 2


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        if len(body) < 10 or not _looks_like_env(body):
            continue

        # File is exposed and shaped like a .env. That alone is critical.
        findings.append(
            Finding(
                severity="critical",
                title=f".env file exposed at {path}",
                evidence=f"GET {path} -> 200 ({len(body)} bytes); KEY=VALUE pattern detected",
                remediation=(
                    "Block .env access publicly + ROTATE every secret in the file:\n"
                    "  Apache: <FilesMatch \"^\\.env\"> Require all denied </FilesMatch>\n"
                    "  Nginx:  location ~ /\\.env { deny all; return 404; }\n"
                    "Move .env outside the docroot if possible (above public_html/)."
                ),
                url=client.url(path),
            )
        )

        # Sniff for specific high-impact secret patterns
        for pat, name in _SECRET_PATTERNS:
            if pat.search(body):
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"{name} leaked in {path}",
                        evidence=f"Pattern {name!r} matched in body of {path} (secret not printed for safety)",
                        remediation=f"ROTATE the leaked {name} immediately. Block .env publicly. Audit all secrets in the file.",
                        url=client.url(path),
                        extra={"secret_type": name},
                    )
                )

    return findings
