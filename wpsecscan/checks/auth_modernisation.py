"""Round-59 #40-46 — Auth modernisation audit.

#40 WebAuthn / passkey support — detect a passkey-capable login form
   (looks for `navigator.credentials.get` or `webauthn` strings in
   login JS).
#41 TOTP / 2FA plugin detection — Wordfence 2FA, Google Authenticator,
   Two-Factor.
#42 SAML SSO depth — `simplesamlphp`, `wp-saml-auth`, OneLogin.
#43 OAuth2 + PKCE — detect public clients that should use PKCE.
#44 Refresh-token rotation — JWT-based REST auth refresh paths.
#45 Session-cookie rotation — does the login response set a new
   `wordpress_logged_in_*` cookie value on re-login? (only a presence
   check — full rotation needs an authenticated test).
#46 Magic-link login — magic-link plugins (Passwordless, MagicLogin).
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


PASSKEY_HINTS = ("navigator.credentials", "webauthn", "PublicKeyCredential", "passkey")

TOTP_PLUGINS = (
    ("Wordfence 2FA",       "/wp-content/plugins/wordfence/wordfence.php"),
    ("Two-Factor",          "/wp-content/plugins/two-factor/two-factor.php"),
    ("Google Authenticator","/wp-content/plugins/google-authenticator/google-authenticator.php"),
    ("WP 2FA",              "/wp-content/plugins/wp-2fa/wp-2fa.php"),
    ("Duo Two-Factor",      "/wp-content/plugins/duo-wordpress/duo_wordpress.php"),
    ("miniOrange 2FA",      "/wp-content/plugins/miniorange-2-factor-authentication/miniorange_2_factor_settings.php"),
)

SAML_PLUGINS = (
    ("WP SAML Auth",        "/wp-content/plugins/wp-saml-auth/wp-saml-auth.php"),
    ("SimpleSAMLphp",       "/wp-content/plugins/simplesaml/simplesaml.php"),
    ("OneLogin SAML SSO",   "/wp-content/plugins/onelogin-saml-sso/onelogin-saml-sso.php"),
    ("miniOrange SAML",     "/wp-content/plugins/miniorange-saml-20-single-sign-on/miniorange_saml_sso_settings_page.php"),
)

OAUTH_PROVIDERS = (
    "/wp-json/oauth/authorize",
    "/wp-json/wp/v2/oauth/authorize",
    "/oauth/authorize",
    "/auth/realms/",  # Keycloak
)

MAGIC_LINK_PLUGINS = (
    ("Passwordless",        "/wp-content/plugins/passwordless-login/passwordless-login.php"),
    ("Magic Login",         "/wp-content/plugins/magic-login/magic-login.php"),
    ("WP Magic Link Login", "/wp-content/plugins/magic-login-pro/magic-login-pro.php"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    # ---- #40 WebAuthn / passkey ----
    step("auth: passkey probe...")
    login_page = await client.get("/wp-login.php")
    login_body = (login_page.text or "") if login_page else ""
    passkey_present = any(h.lower() in login_body.lower() for h in PASSKEY_HINTS)
    if passkey_present:
        findings.append(Finding(
            severity="info",
            title="Passkey / WebAuthn capability detected on login",
            evidence="Found navigator.credentials / webauthn reference in /wp-login.php JS.",
            remediation="Excellent — passkeys are phishing-resistant. Confirm fallback (TOTP / WebAuthn-second-factor) is also enabled.",
            url=target + "/wp-login.php",
        ))
    else:
        findings.append(Finding(
            severity="low",
            title="No passkey / WebAuthn on /wp-login.php",
            evidence="No webauthn JS reference detected.",
            remediation=("Add passkey support via WP-Passkeys plugin or paid Wordfence/iThemes Premium. "
                         "Passkeys are the only practical phishing-resistant 2FA."),
            url=target + "/wp-login.php",
        ))

    # ---- #41 TOTP / 2FA plugin sweep ----
    step("auth: 2FA plugin sweep...")
    seen_2fa = []
    for name, path in TOTP_PLUGINS:
        r = await client.get(path)
        if r is not None and r.status_code == 200 and r.text:
            seen_2fa.append(name)
    if seen_2fa:
        findings.append(Finding(
            severity="info",
            title=f"2FA plugin(s) installed: {', '.join(seen_2fa)}",
            evidence="Plugin file reachable.",
            remediation="No action.",
            url=target,
        ))
    else:
        findings.append(Finding(
            severity="medium",
            title="No 2FA plugin detected",
            evidence="Probed " + str(len(TOTP_PLUGINS)) + " known 2FA plugins, none responded.",
            remediation="Install Two-Factor (core team plugin) or Wordfence 2FA. Required for admin accounts under modern compliance regimes (PCI 4.0 / SOC 2 CC6.1).",
            url=target,
        ))

    # ---- #42 SAML SSO ----
    for name, path in SAML_PLUGINS:
        r = await client.get(path)
        if r is not None and r.status_code == 200 and r.text:
            findings.append(Finding(
                severity="info",
                title=f"SAML SSO plugin detected: {name}",
                evidence=f"{path} reachable.",
                remediation=("Audit the SAML response signature validation. Common bug: accepting "
                             "unsigned assertions when only the SAMLResponse envelope is signed. See also the XSW check."),
                url=target + path,
            ))

    # ---- #43 OAuth2 + PKCE ----
    for path in OAUTH_PROVIDERS:
        r = await client.get(path)
        if r is None or r.status_code not in (200, 302, 400):
            continue
        findings.append(Finding(
            severity="info",
            title=f"OAuth2 authorisation endpoint reachable: {path}",
            evidence=f"GET {path} -> {r.status_code}",
            remediation=("If you operate a public client (mobile / SPA), require `code_challenge` "
                         "(PKCE — RFC 7636) on the authorisation request. Without PKCE, the auth-code "
                         "interception attack is trivial."),
            url=target + path,
        ))

    # ---- #44 Refresh-token rotation ----
    for path in ("/wp-json/jwt-auth/v1/token/refresh",
                 "/wp-json/jwt-auth/v1/token",
                 "/wp-json/simple-jwt-login/v1/auth/refresh"):
        r = await client.get(path)
        if r is None or r.status_code not in (200, 400, 401, 405):
            continue
        findings.append(Finding(
            severity="low",
            title=f"JWT refresh endpoint detected: {path}",
            evidence=f"GET {path} -> {r.status_code}",
            remediation=("Ensure refresh tokens are SINGLE-USE — invalidate the old refresh-token "
                         "on every successful refresh. Many JWT plugins skip this and become "
                         "vulnerable to token-replay."),
            url=target + path,
        ))

    # ---- #45 Session-cookie rotation (presence + Secure/HttpOnly check) ----
    if login_page is not None:
        sc = login_page.headers.get("Set-Cookie", "") if login_page.headers else ""
        if "wordpress_logged_in" in sc:
            flags = []
            if "HttpOnly" not in sc:
                flags.append("HttpOnly missing")
            if "Secure" not in sc:
                flags.append("Secure missing")
            if "SameSite" not in sc:
                flags.append("SameSite missing")
            if flags:
                findings.append(Finding(
                    severity="medium",
                    title="WordPress login cookie missing hardening flags",
                    evidence=f"Set-Cookie: {sc[:200]} ; missing: {', '.join(flags)}",
                    remediation=("Force secure cookies in wp-config.php: define('COOKIE_DOMAIN', '...'); "
                                 "and use a plugin like 'WP Cookie Setter' or filter `auth_cookie` with "
                                 "$secure_only=true."),
                    url=target,
                ))

    # ---- #46 Magic-link ----
    for name, path in MAGIC_LINK_PLUGINS:
        r = await client.get(path)
        if r is not None and r.status_code == 200 and r.text:
            findings.append(Finding(
                severity="low",
                title=f"Magic-link plugin detected: {name}",
                evidence=f"{path} reachable.",
                remediation=("Verify magic-link tokens are: (a) single-use, (b) short-lived (<15min), "
                             "(c) bound to the original requesting IP or User-Agent. Otherwise mailbox "
                             "compromise = WordPress takeover."),
                url=target + path,
            ))

    return findings or [Finding(severity="info", title="Auth modernisation audit — no auth plugins detected",
                                 evidence="", remediation="No action.", url=target)]
