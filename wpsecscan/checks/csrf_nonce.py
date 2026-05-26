"""CSRF / WP-nonce audit.

Look at common state-changing endpoints (the login form, comment form, password
reset, REST endpoints) and confirm they're protected by a nonce or token. WP's
nonce field is `_wpnonce`; some plugins use `_token`, `csrfmiddlewaretoken`,
`authenticity_token`, etc.

This is read-only: we GET the page and inspect the rendered form HTML.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

NONCE_PATTERNS = (
    re.compile(r'name=["\']_wpnonce["\']', re.IGNORECASE),
    re.compile(r'name=["\']_token["\']', re.IGNORECASE),
    re.compile(r'name=["\']csrfmiddlewaretoken["\']', re.IGNORECASE),
    re.compile(r'name=["\']authenticity_token["\']', re.IGNORECASE),
    re.compile(r'name=["\']nonce["\']', re.IGNORECASE),
)
FORM_RE = re.compile(r"<form[^>]*method=['\"]post['\"][^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)

# Pages that commonly hold POST forms. We probe each, find forms, and check.
PAGES = (
    "/",
    "/wp-login.php",
    "/wp-login.php?action=lostpassword",
    "/wp-login.php?action=register",
    "/?p=1",
    "/sample-page/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    unprotected_forms: list[tuple[str, str]] = []  # (page, form-action-attr)
    seen_forms = 0

    for path in PAGES:
        step(f"fetching {path} for form-CSRF inspection...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for form_html in FORM_RE.findall(r.text):
            seen_forms += 1
            has_token = any(p.search(form_html) for p in NONCE_PATTERNS)
            if has_token:
                continue
            # Extract the form action attribute for clarity. Search inside the
            # matched form HTML so we attribute the action to the right form
            # (was searching whole page → first form's action shown for all).
            action_m = re.search(r'<form[^>]*action=["\']([^"\']+)', form_html, re.IGNORECASE)
            action = action_m.group(1) if action_m else "(no action attr)"
            unprotected_forms.append((path, action[:120]))

    if not seen_forms:
        findings.append(
            Finding(
                severity="info",
                title="No POST forms found to audit for CSRF tokens",
                evidence=f"Probed {len(PAGES)} pages; no `<form method=post>` HTML found.",
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    if unprotected_forms:
        lines = "\n".join(f"  - on {pg}: action={act!r}" for pg, act in unprotected_forms[:15])
        findings.append(
            Finding(
                severity="medium",
                title=f"{len(unprotected_forms)} POST form(s) missing visible CSRF/nonce field",
                evidence=(
                    f"POST forms with no `_wpnonce` / `_token` / `csrfmiddlewaretoken` / `nonce` input:\n{lines}\n\n"
                    "Note: this is heuristic — some plugins put the nonce in a header set by JS, which we can't see. "
                    "Manually verify each form post in browser DevTools."
                ),
                remediation=(
                    "WordPress forms should use wp_nonce_field() to embed a `_wpnonce` input and check it server-side "
                    "with wp_verify_nonce() or check_admin_referer(). REST endpoints should require X-WP-Nonce header."
                ),
                url=ctx["target"],
            )
        )
    else:
        findings.append(
            Finding(
                severity="info",
                title=f"All {seen_forms} POST form(s) have visible CSRF/nonce inputs",
                evidence=f"Found nonce/token fields in every form across {len(PAGES)} probed pages.",
                remediation="No action needed for this check.",
                url=ctx["target"],
            )
        )
    return findings
