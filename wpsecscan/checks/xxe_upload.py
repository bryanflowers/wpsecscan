"""XXE via SVG upload probe.

WordPress sites accept SVG uploads via Contact Form 7, Forminator, Gravity Forms,
Ninja Forms, WooCommerce product images, and many others. SVG is XML — so a
DOCTYPE entity reference can:
  - Read local files (file:///etc/passwd via &xxe;)
  - SSRF to internal IPs / cloud metadata
  - Billion-laughs DoS

We probe by sending a BENIGN SVG that includes a DOCTYPE entity reference to a
canary domain. If the response reflects the entity content or our request takes
suspiciously long (entity expansion), the parser is XXE-vulnerable.

Aggressive-only (sends a small file upload).
"""
from __future__ import annotations

import secrets
import time

from ..http import Client
from ..models import Finding

# Common WP upload endpoints. Probes are GET first (to detect presence) then POST.
UPLOAD_PATH_CANDIDATES = (
    "/wp-admin/admin-ajax.php?action=cf7sr-verify",       # Contact Form 7 reCAPTCHA
    "/wp-admin/admin-ajax.php?action=upload-attachment",  # WP core media upload
    "/wp-admin/admin-ajax.php?action=forminator_form_upload_create",  # Forminator
    "/wp-admin/admin-ajax.php?action=gform_drop_uploaded_file",       # Gravity Forms
    "/wp-admin/admin-ajax.php?action=nf_async_request",               # Ninja Forms
)


def _build_xxe_svg(canary: str) -> bytes:
    """Build a small SVG with a DOCTYPE entity reference.

    The entity points to a non-routable canary URL — if the server tries to
    resolve it, we'd see it in DNS logs (we don't operate that DNS, but the
    presence of an attempted resolution is what would matter to a real attacker).
    """
    return (
        f'<?xml version="1.0" standalone="no"?>'
        f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://{canary}.example.invalid/xxe-probe">]>'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2">'
        f'  <text>&xxe;</text>'
        f'</svg>'
    ).encode("utf-8")


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    if not ctx.get("aggressive"):
        findings.append(
            Finding(
                severity="info",
                title="XXE / SVG upload probe skipped (requires --aggressive)",
                evidence="This probe POSTs a small SVG containing a DOCTYPE entity reference.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    canary = "wpsec-xxe-" + secrets.token_hex(4)
    svg_bytes = _build_xxe_svg(canary)

    # Detect endpoints that exist (probe with GET / OPTIONS — many accept either)
    reachable: list[str] = []
    for path in UPLOAD_PATH_CANDIDATES:
        step(f"probing upload endpoint {path[:60]}...")
        r = await client.get(path)
        if r is None:
            continue
        # 200/400 means the endpoint exists; 404 means it doesn't.
        if r.status_code != 404 and r.content:
            reachable.append(path)

    if not reachable:
        findings.append(
            Finding(
                severity="info",
                title="No known WP form upload endpoints reachable — XXE probe skipped",
                evidence=f"None of the {len(UPLOAD_PATH_CANDIDATES)} known WP form upload AJAX paths responded.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    leaks: list[tuple[str, str]] = []
    for path in reachable[:3]:  # limit to 3 attempts to keep noise low
        step(f"sending XXE SVG to {path[:50]}...")
        t0 = time.perf_counter()
        # Send the SVG as a multipart upload
        r = await client.post(
            path,
            content=svg_bytes,
            headers={"Content-Type": "image/svg+xml"},
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        if r is None:
            continue
        body = (r.text or "")[:8000]
        # Indicators:
        #  - The canary string reflected in the response (means parser saw our payload)
        #  - Server took > 8 seconds (entity expansion or DNS resolution attempt)
        #  - HTTP 500 with an XML/entity error string in the body
        suspicious = []
        if canary in body:
            suspicious.append(f"canary `{canary}` reflected in response body")
        if elapsed_ms > 8000:
            suspicious.append(f"response took {elapsed_ms:.0f} ms (>8s) — possible entity resolution attempt")
        body_lc = body.lower()
        for marker in ("docttype", "doctype not allowed", "external entity", "xxe", "entity reference"):
            if marker in body_lc:
                suspicious.append(f"server returned error mentioning '{marker}'")
                break
        if suspicious:
            leaks.append((path, "; ".join(suspicious)))

    if not leaks:
        findings.append(
            Finding(
                severity="info",
                title="XXE / SVG upload probe clean",
                evidence=f"Tested {min(3, len(reachable))} reachable upload endpoint(s); no entity-resolution indicators.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    for path, why in leaks:
        findings.append(
            Finding(
                severity="high",
                title=f"XXE candidate at {path}",
                evidence=(
                    f"POSTed an SVG containing `<!ENTITY xxe SYSTEM \"http://{canary}.example.invalid/...\">`\n"
                    f"Indicator: {why}\n\n"
                    "A confirming attacker can change the entity URL to file:///etc/passwd, "
                    "http://169.254.169.254/latest/meta-data/, or a billion-laughs payload."
                ),
                remediation=(
                    "Disable DOCTYPE in the SVG parser. The plugin owning this endpoint should use "
                    "`libxml_disable_entity_loader(true)` (PHP <8) or pass `LIBXML_NONET | LIBXML_NOENT` "
                    "to its XML parser. For PHP 8+, the loader is disabled by default — confirm the plugin "
                    "isn't manually re-enabling it."
                ),
                url=client.url(path),
            )
        )
    return findings
