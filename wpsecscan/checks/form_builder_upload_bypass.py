"""A23 (v2.6.0) — Form-builder file-upload allow-list bypass detection.

Gravity Forms, WPForms, Formidable Forms, Ninja Forms, and Fluent
Forms all shipped at least one CVE in 2024-2025 where the file-upload
field's MIME / extension allow-list could be bypassed (double-extension
trick, MIME-spoofing via the Form Builder's pre-validated list, etc.).

Passive: fingerprint the plugin via homepage HTML, then surface a
medium advisory recommending version check + the canonical fix.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


_PLUGIN_SIGS = {
    "gravity-forms": ("gravityforms", "/gravityforms/", "GF_PLUGIN_VERSION"),
    "wpforms": ("wpforms", "/wpforms/", "wpforms-frontend"),
    "formidable": ("formidable", "/formidable/", "frm_forms"),
    "ninja-forms": ("ninja-forms", "/ninja-forms/", "nfForms"),
    "fluent-forms": ("fluentform", "/fluentform/", "fluent-forms"),
}


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("form-builder fingerprint: GET /")
    home = await client.get("/")
    body = (home.text or "").lower() if home else ""

    detected: set[str] = set()
    for name, sigs in _PLUGIN_SIGS.items():
        if any(sig.lower() in body for sig in sigs):
            detected.add(name)

    if not detected:
        return findings

    findings.append(Finding(
        severity="medium",
        title=f"Form-builder plugin detected ({', '.join(sorted(detected))}) — verify file-upload patch",
        evidence=(
            f"Detected plugin(s): {', '.join(sorted(detected))}.\n"
            "All listed plugins shipped CVEs in 2024-2025 around file-upload\n"
            "allow-list bypasses (double-extension, MIME spoofing,\n"
            "TOCTOU on the tmp_name). Manual version verification recommended."
        ),
        remediation=(
            "1. Confirm plugin versions are current (use wp-admin → Plugins).\n"
            "2. Audit any form with a file-upload field: confirm the allow-list\n"
            "   uses extension AND MIME AND magic-byte checks (not just extension).\n"
            "3. Add a WAF rule blocking POSTs to /wp-content/uploads/ paths\n"
            "   that don't go through the plugin's expected handler.\n"
            "4. If you don't use file uploads, REMOVE the field from every form."
        ),
        url=client.url("/"),
        extra={"plugins": sorted(detected)},
    ))
    return findings
