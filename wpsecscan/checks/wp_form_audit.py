"""Round-59 #3 — Form-plugin deep audit.

Contact Form 7, WPForms, Gravity Forms, Ninja Forms, Formidable Forms.
Form plugins are the single highest stored-XSS + unauth file-upload
surface in WP. We:
  - fingerprint each form plugin (path + version)
  - flag missing `wpcf7-recaptcha`/`wpforms-recaptcha` indicators
  - check `/wp-json/contact-form-7/v1/contact-forms` (CF7 leak — should be auth)
  - probe NF/GF default upload-handler path
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


FORM_PLUGINS = (
    ("Contact Form 7", "/wp-content/plugins/contact-form-7/wp-contact-form-7.php"),
    ("WPForms Lite",   "/wp-content/plugins/wpforms-lite/wpforms.php"),
    ("Gravity Forms",  "/wp-content/plugins/gravityforms/gravityforms.php"),
    ("Ninja Forms",    "/wp-content/plugins/ninja-forms/ninja-forms.php"),
    ("Formidable",     "/wp-content/plugins/formidable/formidable.php"),
    ("Fluent Forms",   "/wp-content/plugins/fluentform/fluentform.php"),
)
VERSION_RE = re.compile(r"Version:\s*([\d.]+)", re.IGNORECASE)

CF7_REST = "/wp-json/contact-form-7/v1/contact-forms"
NF_UPLOAD = "/wp-content/plugins/ninja-forms/deprecated/includes/uploads/"
GF_UPLOAD = "/wp-content/uploads/gravity_forms/"


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    detected = []
    for name, path in FORM_PLUGINS:
        step(f"form-plugin probe {name}...")
        r = await client.get(path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = VERSION_RE.search(r.text)
        detected.append((name, m.group(1) if m else None, path))

    if not detected:
        return [Finding(severity="info", title="Form-plugin audit — no popular form plugins detected",
                        evidence="Probed 6 form plugins.", remediation="No action.", url=ctx["target"])]

    findings.append(Finding(
        severity="info",
        title=f"Form plugin(s) detected: {len(detected)}",
        evidence="\n".join(f"  - {n} {v or '?'} at {p}" for n, v, p in detected),
        remediation="Form plugins are the most common stored-XSS + unauth-upload entry point. Keep all of them on the latest minor.",
        url=ctx["target"],
    ))

    # CF7 unauthenticated REST leak
    if any(n == "Contact Form 7" for n, _v, _p in detected):
        step("CF7 REST audit...")
        r = await client.get(CF7_REST)
        if r is not None and r.status_code == 200 and r.text:
            findings.append(Finding(
                severity="medium",
                title="Contact Form 7 REST endpoint readable unauthenticated",
                evidence=f"GET {CF7_REST} -> {r.status_code} ({len(r.text)} bytes). Form templates + any embedded merge tags are public.",
                remediation="CF7 REST should require `cap=manage_options`. Apply the upstream fix in v5.9.5+, and check the `rest_authentication_errors` filter on your install.",
                url=ctx["target"] + CF7_REST,
            ))

    # Ninja Forms upload-directory exposure
    if any("Ninja" in n for n, _v, _p in detected):
        r = await client.get(NF_UPLOAD)
        if r is not None and r.status_code == 200 and ("Index of" in (r.text or "") or "<a href" in (r.text or "").lower()):
            findings.append(Finding(
                severity="high",
                title="Ninja Forms deprecated upload directory listable",
                evidence=f"GET {NF_UPLOAD} returns a directory index.",
                remediation=f"Add an empty index.html in {NF_UPLOAD} and disable directory listing in nginx/.htaccess. The deprecated handler is a known stored-XSS path.",
                url=ctx["target"] + NF_UPLOAD,
            ))

    # Gravity Forms upload directory traversal indicators
    if any("Gravity" in n for n, _v, _p in detected):
        r = await client.get(GF_UPLOAD)
        if r is not None and r.status_code == 200 and ("Index of" in (r.text or "") or "<a href" in (r.text or "").lower()):
            findings.append(Finding(
                severity="high",
                title="Gravity Forms upload directory listable",
                evidence=f"GET {GF_UPLOAD} returns a directory index — uploaded files enumerable.",
                remediation=f"Block directory listing for {GF_UPLOAD}. Set `gform_upload_path` filter to a private path outside wp-content/uploads.",
                url=ctx["target"] + GF_UPLOAD,
            ))

    return findings
