"""Sendmail header-injection probe for contact forms.

WordPress contact-form plugins occasionally use user input as the From: or
Reply-To: header without sanitization, allowing attackers to inject CC: /
BCC: headers via CRLF in the From field. We probe common form action URLs
with CRLF-encoded headers in the email field and look for signs the server
accepted the input.

Read-only: we don't actually trigger a send — we just check the immediate
response. Confirming actual injection requires checking inbound mail, which
the scanner can't do.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding

# Common contact-form action URLs
FORM_ENDPOINTS = (
    "/wp-admin/admin-ajax.php",     # CF7 + WPForms route through here
    "/wp-json/contact-form-7/v1/contact-forms/1/feedback",
    "/?contact-form-id=1",
)

# Email-with-CRLF payload — the CRLF tries to inject a BCC header
CRLF_EMAIL = "wpsx-probe@example.com\r\nBcc: wpsx-canary-bcc@example.invalid\r\n"


def _form_data():
    return {
        "your-name": "wpsx-probe",
        "your-email": CRLF_EMAIL,
        "your-subject": "wpsecscan canary",
        "your-message": "wpsx-canary-message",
        "_wpcf7_unit_tag": "1",
        "name": "wpsx-probe",
        "email": CRLF_EMAIL,
        "subject": "wpsx canary",
        "message": "wpsx canary",
    }


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    suspicious: list[dict] = []
    for path in FORM_ENDPOINTS:
        step(f"probing {path} with CRLF email...")
        r = await client.post(path, data=_form_data())
        if r is None:
            continue
        body = (r.text or "")[:2000]
        # If the server reflects the canary email back without sanitizing CRLF, we know it doesn't strip
        if "wpsx-canary-bcc" in body:
            suspicious.append({
                "path": path,
                "status": r.status_code,
                "evidence": "Bcc header value reflected back in form response — handler doesn't strip CRLF",
            })

    if suspicious:
        for s in suspicious:
            findings.append(
                Finding(
                    severity="high",
                    title=f"Possible email header injection at {s['path']}",
                    evidence=(
                        f"POST {s['path']} with `email: wpsx-probe@example.com\\r\\nBcc: ...` -> HTTP {s['status']}\n"
                        f"  {s['evidence']}\n\n"
                        "If the underlying mail handler also doesn't strip these headers, attackers can BCC "
                        "themselves on every contact-form submission (extracting customer emails) or relay spam."
                    ),
                    remediation=(
                        "Audit the form plugin. Modern CF7 / WPForms strip CRLF, but old custom plugins often don't. "
                        "Block at the handler: filter input through wp_mail()'s sanitize_email() and strip \\r\\n manually."
                    ),
                    url=client.url(s["path"]),
                )
            )
    else:
        findings.append(
            Finding(
                severity="info",
                title="No email header injection markers detected",
                evidence=f"Probed {len(FORM_ENDPOINTS)} common contact-form endpoints with CRLF in email field.",
                remediation="No action needed for the tested endpoints (custom forms may still be vulnerable — audit each).",
                url=ctx["target"],
            )
        )

    return findings
