"""F22 (v2.8.1) — WebAuthn / Passkeys RP-ID audit.

Plugins like Passkeys, WP-WebAuthn, and Two-Factor's webauthn
provider must use the eTLD+1 hostname as the RP-ID. Misconfigured
RP-ID lets passkeys made on `app.example.com` work on
`evil.example.com` (or vice versa). We fingerprint the plugin
and emit an advisory; full RP-ID audit requires inspecting the
JS attestation flow, which we can't do passively.
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F22: probing WebAuthn / Passkeys plugins")
    detected = []
    for path, label in (
        ("/wp-content/plugins/passkeys/",       "Passkeys"),
        ("/wp-content/plugins/wp-webauthn/",    "WP-WebAuthn"),
        ("/wp-content/plugins/two-factor/",     "Two-Factor"),
        ("/wp-content/plugins/passwordless-login-with-webauthn/",
         "Passwordless-Login-WebAuthn"),
    ):
        r = await client.head(path)
        if r is not None and r.status_code in (200, 301, 302, 403):
            detected.append(label)
    if not detected:
        return [Finding(severity="info",
                         title="F22: no WebAuthn / Passkeys plugin detected",
                         evidence="None of the 4 fingerprinted plugin paths responded.",
                         remediation="No action needed.",
                         url=ctx["target"])]
    return [Finding(severity="low",
                     title=f"F22: WebAuthn / Passkeys plugin detected ({', '.join(detected)}) — RP-ID audit recommended",
                     evidence=(
                         f"Detected: {', '.join(detected)}. Cannot validate the "
                         "configured Relying-Party ID without an authenticated "
                         "registration flow."),
                     remediation=(
                         "In Settings → Passkeys/WebAuthn, verify the configured "
                         "RP-ID is your eTLD+1 (e.g. `example.com`, not "
                         "`www.example.com` or `*.example.com`). Audit the JS "
                         "registration call for `rp.id === 'your-etld-plus-1'`."),
                     url=ctx["target"])]
