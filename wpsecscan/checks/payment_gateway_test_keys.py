"""Payment-gateway test/sandbox key leak in production JS.

Round-64 #76 — Stripe, PayPal, Braintree all have distinct "test" /
"sandbox" key prefixes. If a production site ships JS that uses a test
key, then (a) all card capture goes to the test environment (lost
revenue + customer support headache) AND (b) the key is now publicly
known. The opposite — a live key embedded client-side — is even worse
but a different check; this one targets the more common dev->prod
deploy bug.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# Each entry: (regex, key-name, kind). 'kind' = "test" or "live-publishable" or "live-secret".
# Note: pk_live_ is meant to be public; we still flag it because some sites mistakenly
# embed sk_live_ which is catastrophic.
_KEY_PATTERNS = (
    (re.compile(r"\bpk_test_[A-Za-z0-9]{24,}"),       "Stripe publishable test key", "test", "medium"),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{24,}"),       "Stripe secret test key",      "test", "high"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{24,}"),       "Stripe secret LIVE key",      "live-secret", "critical"),
    (re.compile(r"\brk_test_[A-Za-z0-9]{24,}"),       "Stripe restricted test key",  "test", "medium"),
    (re.compile(r"\brk_live_[A-Za-z0-9]{24,}"),       "Stripe restricted LIVE key",  "live-secret", "high"),
    (re.compile(r"sandbox_[A-Z0-9]{16,}"),            "PayPal sandbox identifier",   "test", "medium"),
    (re.compile(r"\bsandbox_client_id\b[^\"\\n]*[\"']([A-Za-z0-9_-]{20,})"), "PayPal sandbox client_id", "test", "medium"),
    (re.compile(r"sandbox_tokenization_key\s*=\s*['\"]([A-Za-z0-9_]+)"), "Braintree sandbox token", "test", "medium"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                 "AWS access key ID",           "live-secret", "critical"),
)

_PROBE_PATHS = (
    "/",
    "/checkout/",
    "/cart/",
    "/my-account/",
    "/?page_id=checkout",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    seen: set[tuple[str, str]] = set()  # (key-name, path) — de-dupe across pages
    for path in _PROBE_PATHS:
        step(f"scanning {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        for pat, name, kind, sev in _KEY_PATTERNS:
            m = pat.search(body)
            if m:
                key_id = (name, path)
                if key_id in seen:
                    continue
                seen.add(key_id)
                masked = m.group(0)[:12] + "..." + m.group(0)[-4:]
                findings.append(
                    Finding(
                        severity=sev,
                        title=f"{name} embedded in {path}",
                        evidence=f"Pattern matched at {path}\n  Masked: {masked}",
                        remediation=(
                            "If this is a TEST key on production: payments are being captured in the test environment instead of live.\n"
                            "  Action: switch the gateway plugin to its 'live' mode + regenerate keys from the gateway dashboard.\n"
                            "If this is a LIVE SECRET key (sk_live_) client-side: ROTATE IMMEDIATELY — the key is now public.\n"
                            "  Action: gateway dashboard → revoke + reissue. Secret keys must NEVER be in HTML/JS."
                            if "secret" in name.lower() or kind == "live-secret"
                            else "Verify the test key is intentional on this environment. Production sites should use live keys, not test."
                        ),
                        url=client.url(path),
                        extra={"key_type": name, "kind": kind},
                    )
                )

    return findings
