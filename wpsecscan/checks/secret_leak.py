"""Accidental secret-leak detection.

Scans page bodies for patterns that look like API keys / tokens left in
the HTML or in JS files. WordPress sites frequently leak Stripe keys,
Google Maps API keys, Mailchimp keys, etc. when developers build client-side
configs directly into the page.

Detection is regex-based; we redact the matched value before placing it in
the finding so the report itself doesn't leak the secret.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Each entry: (name, severity, regex). The regex's group(1) is what we redact.
SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern], ...] = (
    ("Stripe live secret key",     "critical", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})", re.IGNORECASE)),
    ("Stripe live publishable",    "low",      re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})", re.IGNORECASE)),
    ("Stripe test secret key",     "medium",   re.compile(r"\b(sk_test_[0-9a-zA-Z]{24,})", re.IGNORECASE)),
    ("AWS access key ID",          "high",     re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    # 40-char base64 strings are extremely common (hashes, CSS-loader IDs,
    # build manifests). Require a leading `=`/`:`/quote so it looks like an
    # assignment — plus the AWS context check below. Whitespace was previously
    # in the char class but that includes newlines, so any 40-char hash at a
    # line start would trip the gate.
    ("AWS secret access key",      "critical",
        re.compile(r"(?<=[=:\"'])([A-Za-z0-9/+=]{40})(?![0-9A-Za-z+/=])", re.IGNORECASE)),
    ("Google API key",             "medium",   re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("GitHub personal access token","critical",re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("Slack bot/app token",        "critical", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b")),
    # OpenAI uses three known shapes: classic sk-<48>, project sk-proj-<...>,
    # service-account sk-svcacct-<...>. Anthropic uses sk-ant-<...>. A bare
    # `sk-<anything>` is too generic and matches custom JWT secrets, SDK tokens,
    # etc. — downgrade unless it matches a vendor prefix.
    ("OpenAI/Anthropic API key",   "critical",
        re.compile(r"\b(sk-(?:proj-|svcacct-|ant-)[A-Za-z0-9_\-]{20,})\b")),
    ("Generic sk- prefixed secret","low",
        re.compile(r"\b(sk-[A-Za-z0-9_\-]{40,})\b")),
    ("Mailgun API key",            "high",     re.compile(r"\b(key-[0-9a-f]{32})\b")),
    ("Mailchimp API key",          "high",     re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b")),
    ("SendGrid API key",           "high",     re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    ("Twilio Account SID",         "low",      re.compile(r"\b(AC[0-9a-f]{32})\b")),
    ("JWT token in source",        "low",      re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b")),
    # Bounded the lookahead distance to 200 chars to avoid catastrophic
    # backtracking on large minified JS bundles containing many 40-char
    # base64 sequences before any "cloudflare" mention.
    ("Cloudflare API token",       "high",     re.compile(r"\b([A-Za-z0-9_\-]{40})(?=.{0,200}cloudflare)", re.IGNORECASE | re.DOTALL)),
    ("Generic private key (PEM)",  "critical", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)")),
)

# Reduce false positives: AWS secret-style 40-char strings need to appear
# near AWS context words to be considered a real key.
AWS_CONTEXT_WORDS = ("aws", "amazon", "s3", "amazonaws", "access_key_id", "secret_access_key", "AKIA")

SCAN_PATHS = (
    "/",
    "/wp-login.php",
    "/?p=1",
    "/sample-page/",
    "/feed/",
    # JS bundle paths that frequently leak frontend configs
    "/wp-content/themes/twentytwentyfour/assets/js/scripts.js",
    "/wp-content/themes/twentytwentyfour/dist/index.js",
)


def _redact(value: str) -> str:
    """Show only first 4 and last 4 chars."""
    if len(value) <= 12:
        return "[REDACTED]"
    return value[:4] + "[...REDACTED..." + str(len(value) - 8) + " chars...]" + value[-4:]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    bodies: list[tuple[str, str]] = []  # (path, body)
    for path in SCAN_PATHS:
        step(f"fetching {path} for secret scan...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        bodies.append((path, r.text))

    if not bodies:
        return findings

    found: list[tuple[str, str, str, str]] = []  # (name, severity, path, redacted)
    for name, sev, pattern in SECRET_PATTERNS:
        for path, body in bodies:
            for m in pattern.finditer(body):
                value = m.group(1)
                if name == "AWS secret access key":
                    # context-gate: only flag if AWS context word appears within 200 chars
                    span_start = max(0, m.start() - 200)
                    span_end = min(len(body), m.end() + 200)
                    context = body[span_start:span_end].lower()
                    if not any(w in context for w in AWS_CONTEXT_WORDS):
                        continue
                found.append((name, sev, path, _redact(value)))

    # Dedupe by (name, redacted) so the same key found in 4 pages = 1 finding
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str, str, str]] = []
    for entry in found:
        key = (entry[0], entry[3])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)

    for name, sev, path, redacted in deduped:
        findings.append(
            Finding(
                severity=sev,
                title=f"{name} present in page source",
                evidence=(
                    f"Discovered at: {path}\n"
                    f"  Value (redacted): {redacted}\n\n"
                    "Secrets in HTML/JS responses are visible to every site visitor and search engine."
                ),
                remediation=(
                    f"1. Rotate the {name.lower()} IMMEDIATELY at the provider — assume the original is compromised.\n"
                    "2. Move the secret out of client-side code. Sensitive ops should be proxied through a server-side endpoint that holds the secret on the server.\n"
                    "3. Audit access/billing logs for unauthorized use."
                ),
                url=client.url(path),
                extra={"secret_type": name},
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No accidental secret patterns detected",
                evidence=f"Scanned {len(bodies)} response bodies against {len(SECRET_PATTERNS)} secret patterns.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings
