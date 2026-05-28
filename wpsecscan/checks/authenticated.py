"""Authenticated scan — logs in as an admin and inspects internal state.

Three login flows supported (preference order):
  1. WP Application Password (ctx['auth_app_password'] — WP 5.6+, recommended)
  2. Companion-plugin one-time token (ctx['companion_token'] — see wp-plugin/)
  3. Cookie-based wp-login.php form POST (ctx['auth_user']/['auth_pass'])
     - 2FA: if site requires TOTP, ctx['auth_totp'] is consumed automatically

Performs the following inspections once logged in:
  - /wp-admin/users.php → admin-role roster + 2FA-status fingerprint
  - /wp-admin/plugins.php → definitive plugin enumeration (active/inactive)
  - /wp-admin/themes.php → installed-but-inactive themes (attack surface)
  - /wp-admin/site-health.php → Site Health critical issues
  - /wp-admin/options.php → dangerous flags (default_role, registration)
  - /wp-admin/update-core.php → pending core/plugin/theme updates
  - /wp-json/wp/v2/users?context=edit → full user data (emails)
  - WP REST diagnostics via companion plugin if token is set
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding

LOGIN_FORM_RE  = re.compile(r'name=["\']log["\']', re.IGNORECASE)
ADMIN_BAR_RE   = re.compile(r'<div\s+id=["\']wpadminbar["\']', re.IGNORECASE)
PLUGIN_ROW_RE  = re.compile(r'<tr[^>]+id=["\']([a-z0-9_\-]+)["\']\s+class=["\'](active|inactive)', re.IGNORECASE)
THEME_NAME_RE  = re.compile(r'<h2[^>]+class=["\']theme-name["\'][^>]*>(.*?)</h2>', re.IGNORECASE | re.DOTALL)
USER_ROW_RE    = re.compile(r'<td[^>]+data-colname=["\']Username["\'][^>]*>(.*?)</td>', re.IGNORECASE | re.DOTALL)
USER_ROLE_RE   = re.compile(r'<td[^>]+data-colname=["\']Role["\'][^>]*>(.*?)</td>',     re.IGNORECASE | re.DOTALL)
TOTP_PROMPT_RE = re.compile(r'(name=["\']wfls_two_factor_code["\']|two-factor|totp|authenticator code|verification code)', re.IGNORECASE)

# #3 — CAPTCHA / Turnstile / hCaptcha markers. When the login form contains
# any of these, posting credentials is futile; abort with a clear error.
CAPTCHA_RE = re.compile(
    r'g-recaptcha|grecaptcha\.|recaptcha/api\.js'
    r'|h-captcha|hcaptcha\.|hcaptcha/api'
    r'|cf-turnstile|turnstile\.|challenges\.cloudflare\.com',
    re.IGNORECASE,
)

# #4 — Login-failure-mode fingerprints. Used to give the user a precise
# error instead of a generic "auth failed".
LOGIN_ERROR_BLOCK_RE = re.compile(
    r'<div\s+id=["\']login_error["\'][^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL,
)
WRONG_USERNAME_RE = re.compile(
    r"(?:unknown username|invalid username|the username[^<]{0,40}is incorrect)",
    re.IGNORECASE,
)
WRONG_PASSWORD_RE = re.compile(
    r"(?:incorrect password|the password you entered[^<]{0,40}is incorrect)",
    re.IGNORECASE,
)
LOCKED_OUT_RE = re.compile(
    r"(?:locked out|too many failed|temporarily disabled|please try again later"
    r"|access denied|blocked by|ip[- ]banned|you have been blocked)",
    re.IGNORECASE,
)


def classify_login_failure(status: int, body: str) -> tuple[str, str]:
    """Return (category, explanation). Categories:
       wrong-password / wrong-username / locked-out / captcha-required /
       ip-banned / unknown.
    """
    body_lc = (body or "").lower()
    # 4xx + body indicators
    if status in (403, 406, 418, 429):
        return ("locked-out",
                f"Server returned HTTP {status}, indicating WAF / fail2ban / "
                "Wordfence has temporarily blocked this IP from logging in.")
    if CAPTCHA_RE.search(body or ""):
        return ("captcha-required",
                "The login page requires a human CAPTCHA challenge "
                "(reCAPTCHA / hCaptcha / Cloudflare Turnstile). Headless "
                "scanners can't solve these — disable the challenge for the "
                "scanner's source IP or use --auth-app-password instead.")
    err = LOGIN_ERROR_BLOCK_RE.search(body or "")
    err_text = err.group(1) if err else ""
    if LOCKED_OUT_RE.search(body_lc):
        return ("locked-out",
                "Login form body contains a lock-out marker ('too many "
                "attempts' / 'blocked' / 'please try again later'). "
                "Wait the lockout window or whitelist this IP.")
    if WRONG_USERNAME_RE.search(body_lc):
        return ("wrong-username",
                "Login form reported 'unknown username'. The user account "
                "doesn't exist on this site.")
    if WRONG_PASSWORD_RE.search(body_lc):
        return ("wrong-password",
                "Login form reported 'incorrect password' for this user.")
    if err_text:
        return ("rejected",
                f"Login form returned an error: {re.sub(r'<[^>]+>', '', err_text)[:200]}")
    return ("unknown",
            f"Login didn't land at /wp-admin/ (status={status}) but no "
            "specific failure marker was detected. Try WPSECSCAN_AUTH_DEBUG=1 "
            "to see each step.")

# #1: extract the _wpnonce field from a wp-login.php GET. Modern WP + every
# major security plugin requires it on the POST.
NONCE_RE = re.compile(
    r'<input[^>]+name=["\']_wpnonce["\'][^>]+value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# #2: browser-like User-Agent. The "WPSecScan/1.0 (authenticated-scan)" UA
# triggered fail2ban + Wordfence layer-7 blocks. This Chrome UA is close
# enough to a real Chrome desktop client that it's not auto-banned. Operator
# may override with WPSECSCAN_AUTH_USER_AGENT env var.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def _auth_ua() -> str:
    """Override-able User-Agent for auth requests."""
    return os.environ.get("WPSECSCAN_AUTH_USER_AGENT", _BROWSER_UA)


def _auth_debug_enabled() -> bool:
    return bool(os.environ.get("WPSECSCAN_AUTH_DEBUG"))


# #5 — paths to try when /wp-login.php doesn't exist. Plugins that
# rename the login URL are common (WPS Hide Login, Rename wp-admin,
# Loginizer, manual rewrites). Order matters: try the canonical
# path first so the common case stays fast.
_LOGIN_PATH_CANDIDATES = (
    "/wp-login.php",
    "/login",
    "/login/",
    "/admin",
    "/admin/",
    "/backend",
    "/backend/",
    "/dashboard",
    "/dashboard/",
    "/wp-admin/login.php",
    "/wp-admin",
)


# #10 — per-site auth-strategy cache. Once we've discovered "this site
# needs nonce + browser UA + login path X + 2FA field foo", stash it
# so re-scans skip the discovery dance.
def _strategy_cache_path(host: str) -> Path:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    d = home / "auth_strategy"
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-z0-9_.-]+", "-", host.lower()) or "host"
    return d / f"{safe}.json"


def load_strategy(host: str) -> dict:
    """Read the cached auth strategy for a host. Returns {} on miss."""
    try:
        import json as _json
        p = _strategy_cache_path(host)
        if p.exists():
            return _json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        pass
    return {}


def save_strategy(host: str, **kwargs) -> None:
    """Update the cached auth strategy for a host with the keys provided.
    Existing keys are preserved; new ones overwrite. Best-effort."""
    try:
        import json as _json
        p = _strategy_cache_path(host)
        existing = load_strategy(host)
        existing.update(kwargs)
        existing["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        p.write_text(_json.dumps(existing, indent=2), encoding="utf-8")
    except OSError:
        pass


async def discover_login_url(c: httpx.AsyncClient, base: str, host: str) -> str | None:
    """#5: probe candidate login URLs until one returns the WP login form.
    Checks the env override WPSECSCAN_LOGIN_PATH first, then the cached
    strategy, then a small candidate list. Returns the absolute URL of
    the found login page (or None when nothing works)."""
    # Honour env-var override (operator knows the path).
    override = os.environ.get("WPSECSCAN_LOGIN_PATH", "").strip()
    if override:
        path = "/" + override.lstrip("/")
        candidates = (path,) + tuple(p for p in _LOGIN_PATH_CANDIDATES if p != path)
    else:
        candidates = _LOGIN_PATH_CANDIDATES
    # Honour the per-site cache.
    cached = load_strategy(host).get("login_path")
    if cached:
        candidates = (cached,) + tuple(p for p in candidates if p != cached)

    for path in candidates:
        try:
            r = await c.get(base + path)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and LOGIN_FORM_RE.search(r.text or ""):
            _auth_debug(host, f"login form discovered at {path}", r)
            # Cache the discovered path so subsequent scans skip the probe.
            save_strategy(host, login_path=path)
            return base + path
    _auth_debug(host, "no login form found at any candidate path")
    return None


def _auth_debug_log_path(host: str) -> Path:
    """One log file per host so subsequent runs append cleanly."""
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    d = home / "auth-debug"
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-z0-9_.-]+", "-", host.lower()) or "host"
    return d / f"{safe}.log"


def _auth_debug(host: str, step: str, response: httpx.Response | None = None,
                  extra: str = "") -> None:
    """#9: append one entry per auth step to ~/.wpsecscan/auth-debug/{host}.log
    when WPSECSCAN_AUTH_DEBUG=1. Sanitises Set-Cookie + Authorization headers
    so the log is shareable for support."""
    if not _auth_debug_enabled():
        return
    try:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        lines = [f"--- {ts}  {step}"]
        if response is not None:
            lines.append(f"  url:    {response.request.method} {response.url}")
            lines.append(f"  status: {response.status_code}")
            for k, v in response.headers.items():
                kl = k.lower()
                if kl in ("set-cookie", "authorization", "x-wpsecscan-token",
                           "cookie", "x-csrf-token"):
                    lines.append(f"  header: {k}: [REDACTED ({len(str(v))} chars)]")
                else:
                    lines.append(f"  header: {k}: {v}")
            # C18 (v2.7.2) — pipe through mask_private so partial
            # nonces / JWTs / cookies in the WP login HTML response
            # don't leak into the auth-debug log file (which lives
            # under ~/.wpsecscan and may be uploaded as part of a
            # bug report).
            from ..ai_safety import mask_private as _mask
            body = _mask((response.text or "")[:500]).replace("\n", " ")
            lines.append(f"  body[:500]: {body}")
        if extra:
            lines.append(f"  note: {extra}")
        with _auth_debug_log_path(host).open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n\n")
    except OSError:
        pass  # debug log must never break the scan


# Per-call mutable holder for the LAST failure reason so the caller can
# surface it. Threaded via the module-level _LAST_FAILURE dict because the
# function signature was already 4 args and callers don't want a tuple.
_LAST_FAILURE: dict[str, tuple[str, str]] = {}


def last_failure_for(target: str) -> tuple[str, str] | None:
    """Read the last classify_login_failure() output for a given target host."""
    parsed = urlparse(target)
    return _LAST_FAILURE.get(parsed.hostname or "")


async def _login_cookie(target: str, user: str, password: str,
                          totp: str | None = None) -> httpx.AsyncClient | None:
    """Log into WP via the wp-login.php form. Supports common 2FA prompts
    when `totp` is supplied. Returns an authenticated httpx client or None
    on failure.

    Hardened for real-world WP sites:
      - Sends a current-Chrome User-Agent (env override:
        WPSECSCAN_AUTH_USER_AGENT) to avoid fail2ban/Wordfence layer-7 bans
      - Parses the `_wpnonce` field from the GET form before POSTing
      - Captures Set-Cookie from every step of the redirect chain
      - When WPSECSCAN_AUTH_DEBUG=1, writes a sanitised log of every step
        to ~/.wpsecscan/auth-debug/{host}.log
    """
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname or "host"

    # #8: explicit jar so we can capture cookies set at each hop.
    jar = httpx.Cookies()
    c = httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=True,
        cookies=jar,
        headers={
            "User-Agent": _auth_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    # #5: discover the login URL (handles WPS Hide Login + renamed admins).
    login_url = await discover_login_url(c, base, host)
    if not login_url:
        _LAST_FAILURE[host] = ("login-url-not-found",
            "Couldn't locate a WordPress login form at /wp-login.php or any "
            "of the common renamed paths (/login, /admin, /backend, "
            "/dashboard). If the login URL is custom, set "
            "WPSECSCAN_LOGIN_PATH=/your/login/path and re-run.")
        await c.aclose()
        return None
    try:
        r = await c.get(login_url)
    except httpx.HTTPError as e:
        _auth_debug(host, f"GET {login_url} — transport error", None, str(e))
        await c.aclose()
        return None
    _auth_debug(host, f"GET {login_url}", r)
    if r.status_code != 200 or not LOGIN_FORM_RE.search(r.text or ""):
        _LAST_FAILURE[host] = classify_login_failure(r.status_code, r.text or "")
        _auth_debug(host, "login form not found at discovered URL", None,
                     f"status={r.status_code}; reason={_LAST_FAILURE[host][0]}")
        await c.aclose()
        return None

    # #3: abort early if the login form requires a CAPTCHA — posting
    # credentials would be futile and likely trigger a lockout.
    if CAPTCHA_RE.search(r.text or ""):
        _LAST_FAILURE[host] = ("captcha-required",
            "wp-login.php form requires a CAPTCHA challenge "
            "(reCAPTCHA / hCaptcha / Cloudflare Turnstile). Use "
            "--auth-app-password instead, or disable the challenge for the "
            "scanner's source IP.")
        _auth_debug(host, "CAPTCHA detected on login form — aborting")
        await c.aclose()
        return None

    # #1: extract _wpnonce from the GET form. Wordfence + Solid + iThemes
    # reject any POST that doesn't carry the matching nonce.
    nonce_match = NONCE_RE.search(r.text or "")
    nonce_value = nonce_match.group(1) if nonce_match else ""

    post_data = {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/",
        "testcookie": "1",
    }
    if nonce_value:
        post_data["_wpnonce"] = nonce_value

    try:
        r = await c.post(
            login_url,
            data=post_data,
            headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check"},
        )
    except httpx.HTTPError as e:
        _auth_debug(host, f"POST {login_url} — transport error", None, str(e))
        await c.aclose()
        return None
    _auth_debug(host, f"POST {login_url}", r,
                  extra=f"nonce_sent={bool(nonce_value)}")

    # Handle 2FA prompt (Two-Factor / Wordfence / iThemes)
    if TOTP_PROMPT_RE.search(r.text or ""):
        if not totp:
            _auth_debug(host, "2FA prompt detected, no totp provided")
            await c.aclose()
            return None
        # Best-effort: post the TOTP back to the same URL. Different plugins
        # use different field names — try the 3 most common.
        # #6: expanded 2FA field names — covers ~10 of the most-used WP
        # 2FA plugins. The previously-cached winning field (if any) is
        # tried first so re-scans don't iterate the full list.
        _TOTP_FIELDS = (
            "authcode",              # Two Factor (core)
            "wfls_two_factor_code",  # Wordfence Login Security
            "two-factor-code",       # iThemes Security / Solid
            "isc_2fa_code",          # Solid Security (newer)
            "wp_2fa_app_code",       # WP 2FA app (Melapress)
            "wp_2fa_backup_code",    # WP 2FA backup code
            "duo_passcode",          # Duo Security
            "miniorange_2fa_otp",    # miniOrange 2FA
            "miniorange_2fa_token",  # miniOrange (older)
            "wdf_otp",               # Defender Security
            "g2fa_code",             # Google Authenticator for WordPress
            "provider_name",         # Two Factor (provider field)
        )
        cached_field = load_strategy(host).get("totp_field")
        if cached_field:
            ordered = (cached_field,) + tuple(f for f in _TOTP_FIELDS if f != cached_field)
        else:
            ordered = _TOTP_FIELDS
        for field in ordered:
            try:
                r2 = await c.post(
                    login_url,
                    data={field: totp, "wp-submit": "Authenticate", "redirect_to": base + "/wp-admin/"},
                )
                _auth_debug(host, f"POST 2FA with field={field}", r2)
                if ADMIN_BAR_RE.search(r2.text or "") or "/wp-admin" in str(r2.url):
                    # #10: cache the winning 2FA field name for next run.
                    save_strategy(host, totp_field=field, nonce_required=bool(nonce_value))
                    _LAST_FAILURE.pop(host, None)
                    return c
            except httpx.HTTPError as e:
                _auth_debug(host, f"POST 2FA field={field} transport error", None, str(e))
                continue
        await c.aclose()
        return None

    if ADMIN_BAR_RE.search(r.text or "") or "/wp-admin" in str(r.url):
        _auth_debug(host, "auth success via admin-bar / wp-admin redirect")
        save_strategy(host, nonce_required=bool(nonce_value))
        _LAST_FAILURE.pop(host, None)
        return c
    if any(c_name.startswith("wordpress_logged_in_") for c_name in jar.keys()):
        _auth_debug(host, "auth success via wordpress_logged_in_* cookie")
        save_strategy(host, nonce_required=bool(nonce_value))
        _LAST_FAILURE.pop(host, None)
        return c
    # #4: classify the failure so the caller can surface a precise reason.
    _LAST_FAILURE[host] = classify_login_failure(r.status_code, r.text or "")
    _auth_debug(host, "auth failed — no admin marker", None,
                  f"final url={r.url}; reason={_LAST_FAILURE[host][0]}")
    await c.aclose()
    return None


async def _login_app_password(target: str, user: str, app_password: str) -> httpx.AsyncClient | None:
    """Use a WP Application Password (WP 5.6+) via HTTP Basic auth.
    Verifies by hitting /wp-json/wp/v2/users/me with ?context=edit."""
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname or "host"
    # WP accepts the password with or without spaces; strip for safety
    clean_pw = app_password.replace(" ", "")
    c = httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=True,
        auth=(user, clean_pw),
        headers={"User-Agent": _auth_ua()},
    )
    try:
        r = await c.get(base + "/wp-json/wp/v2/users/me?context=edit")
    except httpx.HTTPError as e:
        _auth_debug(host, "GET /wp-json/wp/v2/users/me — transport error", None, str(e))
        await c.aclose()
        return None
    _auth_debug(host, "GET /wp-json/wp/v2/users/me (AP)", r)
    if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
        try:
            payload = r.json()
            if isinstance(payload, dict) and payload.get("id"):
                return c
        except ValueError:
            pass

    # #7: REST is locked-down on this site (typical hardening: hide
    # /wp-json/* from anon, or proxy strips Basic auth). Try XML-RPC as a
    # fallback — wp.getProfile accepts the same Application Password and
    # confirms the credentials work even when REST is closed.
    if r.status_code in (401, 403, 404):
        _auth_debug(host, "REST returned non-200, trying XML-RPC fallback",
                     None, f"rest_status={r.status_code}")
        try:
            xml_body = (
                "<?xml version='1.0'?>"
                "<methodCall><methodName>wp.getProfile</methodName>"
                "<params>"
                f"<param><value><int>1</int></value></param>"
                f"<param><value><string>{user}</string></value></param>"
                f"<param><value><string>{clean_pw}</string></value></param>"
                "</params></methodCall>"
            )
            r2 = await c.post(
                base + "/xmlrpc.php",
                content=xml_body,
                headers={"Content-Type": "text/xml"},
            )
            _auth_debug(host, "POST /xmlrpc.php wp.getProfile", r2)
            if r2.status_code == 200 and "<methodResponse>" in (r2.text or "") \
                    and "<fault>" not in (r2.text or ""):
                # XML-RPC accepted the AP — credentials are valid; the client
                # has Basic-auth set and the cookie jar carries any session
                # cookies XML-RPC issued. Return it.
                save_strategy(host, app_password_via="xmlrpc")
                return c
        except httpx.HTTPError as e:
            _auth_debug(host, "XML-RPC fallback transport error", None, str(e))

    await c.aclose()
    return None


async def _fetch_users_rest(auth: httpx.AsyncClient, base: str) -> list[dict]:
    """Pull /wp-json/wp/v2/users?context=edit — gives emails + roles."""
    try:
        r = await auth.get(base + "/wp-json/wp/v2/users?context=edit&per_page=100")
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    try:
        d = r.json()
        return d if isinstance(d, list) else []
    except ValueError:
        return []


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    user = ctx.get("auth_user")
    pwd = ctx.get("auth_pass")
    app_pw = ctx.get("auth_app_password")
    totp = ctx.get("auth_totp")
    companion_token = ctx.get("companion_token")

    if not any((pwd, app_pw, companion_token)):
        return [Finding(
            severity="info",
            title="Authenticated scan skipped (no credentials)",
            evidence=("Pass --auth-user + (--auth-pass OR --auth-app-password), "
                       "OR --companion-token (with the companion plugin installed)."),
            remediation="No action needed.",
            url=ctx["target"],
        )]

    parsed = urlparse(ctx["target"])
    base = f"{parsed.scheme}://{parsed.netloc}"

    # ---- Companion-token flow (richest data, single round-trip) ----
    if companion_token:
        step("companion plugin handshake...")
        try:
            async with httpx.AsyncClient(timeout=20.0) as c:
                r = await c.get(
                    base + "/wp-json/wpsecscan/v1/diagnostics",
                    headers={"X-WPSecScan-Token": companion_token,
                             "User-Agent": "WPSecScan/1.0 (companion)"},
                )
            if r.status_code == 200:
                try:
                    diag = r.json()
                except ValueError:
                    diag = {}
                if isinstance(diag, dict):
                    findings.extend(_companion_findings(diag, base))
                    return findings
            findings.append(Finding(
                severity="medium",
                title=f"WPSecScan companion plugin returned {r.status_code}",
                evidence=f"GET /wp-json/wpsecscan/v1/diagnostics -> {r.status_code}. Token may be invalid, expired, or already used.",
                remediation="Generate a fresh token in WP admin → Settings → WPSecScan companion.",
                url=base + "/wp-json/wpsecscan/v1/diagnostics",
            ))
        except httpx.HTTPError as e:
            findings.append(Finding(
                severity="info",
                title="Companion plugin not reachable",
                evidence=f"HTTPError: {type(e).__name__}",
                remediation="Install + activate the WPSecScan companion plugin, or fall through to cookie auth.",
                url=ctx["target"],
            ))
        # Fall through to cookie/app-password if companion fails

    # ---- App-password flow (preferred for WP 5.6+) ----
    auth: httpx.AsyncClient | None = None
    auth_method = ""
    if app_pw and user:
        step("trying WP Application Password...")
        auth = await _login_app_password(ctx["target"], user, app_pw)
        if auth:
            auth_method = "Application Password"

    # ---- Cookie flow (fallback) ----
    if auth is None and pwd and user:
        step("logging in with admin credentials...")
        auth = await _login_cookie(ctx["target"], user, pwd, totp=totp)
        if auth:
            auth_method = "cookie (wp-login.php)"

    if auth is None:
        # #4: surface the specific failure reason when we know it.
        last = last_failure_for(ctx["target"])
        if last is not None:
            cat, explanation = last
            findings.append(Finding(
                severity="medium",
                title=f"Authentication failed — {cat}",
                evidence=explanation,
                remediation=(
                    "Set WPSECSCAN_AUTH_DEBUG=1 and re-run to see a step-by-step "
                    "log at ~/.wpsecscan/auth-debug/{host}.log. For 2FA, generate "
                    "an Application Password and use --auth-app-password instead "
                    "of --auth-pass."
                ),
                url=ctx["target"],
            ))
        else:
            findings.append(Finding(
                severity="medium",
                title="Authentication failed — credentials rejected or 2FA prompt unhandled",
                evidence=("Neither App Password nor cookie login succeeded. "
                           "If the site uses 2FA, supply --auth-totp <code>. If it uses "
                           "a custom login URL (WPS Hide Login), the cookie flow can't find it."),
                remediation="Verify credentials. For 2FA, generate an Application Password instead.",
                url=ctx["target"],
            ))
        return findings

    findings.append(Finding(
        severity="info",
        title=f"Authenticated as {user} via {auth_method}",
        evidence="Authenticated checks will now run.",
        remediation="No action.",
        url=ctx["target"],
    ))

    try:
        # ---- 1. REST users (emails + roles) ----
        step("REST: pulling /wp-json/wp/v2/users?context=edit...")
        users = await _fetch_users_rest(auth, base)
        admins = [u for u in users if "administrator" in [r.lower() for r in (u.get("roles") or [])]]
        if len(admins) > 1:
            findings.append(Finding(
                severity="medium",
                title=f"{len(admins)} administrator account(s) (REST)",
                evidence="\n".join(f"  - {a.get('username') or a.get('slug', '?')} "
                                     f"<{a.get('email', 'no-email')}>"
                                     for a in admins[:10]),
                remediation="Audit each admin. Demote anyone who doesn't need admin. Force 2FA on all admin accounts.",
                url=base + "/wp-admin/users.php?role=administrator",
            ))
        if users:
            never_login = [u for u in users
                            if not u.get("meta", {}).get("last_login")]
            if never_login:
                findings.append(Finding(
                    severity="low",
                    title=f"{len(never_login)} user(s) with no last_login meta",
                    evidence="May indicate stale accounts that could be deleted.",
                    remediation="Audit for inactive accounts and delete or downgrade them.",
                    url=base + "/wp-admin/users.php",
                ))

        # ---- 2. HTML admin pages (fall-back / cross-reference) ----
        step("admin: /wp-admin/users.php?role=administrator...")
        try:
            r = await auth.get(base + "/wp-admin/users.php?role=administrator")
            usernames = USER_ROW_RE.findall(r.text or "")
            roles = USER_ROLE_RE.findall(r.text or "")
            admins_html = []
            for u_html, role_html in zip(usernames, roles):
                u = re.sub(r"<[^>]+>", "", u_html).strip()
                role = re.sub(r"<[^>]+>", "", role_html).strip()
                if "administrator" in role.lower():
                    admins_html.append(u)
            if len(admins_html) > 1 and not admins:  # only if REST didn't already cover
                findings.append(Finding(
                    severity="medium",
                    title=f"{len(admins_html)} administrator account(s) (HTML)",
                    evidence="Administrator-role users:\n" + "\n".join(f"  - {a}" for a in admins_html),
                    remediation="Audit + reduce admin count. Force 2FA.",
                    url=base + "/wp-admin/users.php?role=administrator",
                ))
        except httpx.HTTPError:
            pass

        # ---- 3. Plugin enumeration ----
        step("admin: /wp-admin/plugins.php for definitive plugin list...")
        try:
            r = await auth.get(base + "/wp-admin/plugins.php")
            plugins_seen = PLUGIN_ROW_RE.findall(r.text or "")
            if plugins_seen:
                active = [p for p, s in plugins_seen if s.lower() == "active"]
                inactive = [p for p, s in plugins_seen if s.lower() == "inactive"]
                findings.append(Finding(
                    severity="info",
                    title=f"Definitive plugin list: {len(active)} active, {len(inactive)} inactive",
                    evidence=(("Active:\n" + "\n".join(f"  - {p}" for p in active[:25]) + "\n" if active else "")
                              + ("Inactive:\n" + "\n".join(f"  - {p}" for p in inactive[:25]) if inactive else "")),
                    remediation="Delete inactive plugins — they still receive PHP execution if a CVE drops while installed.",
                    url=base + "/wp-admin/plugins.php",
                ))
                ctx.setdefault("shared", {}).setdefault("plugins", {})
                for slug, _state in plugins_seen:
                    ctx["shared"]["plugins"].setdefault(slug, None)
        except httpx.HTTPError:
            pass

        # ---- 4. Themes ----
        step("admin: /wp-admin/themes.php...")
        try:
            r = await auth.get(base + "/wp-admin/themes.php")
            themes = [re.sub(r"<[^>]+>", "", m).strip()
                       for m in THEME_NAME_RE.findall(r.text or "")]
            inactive_themes = themes[1:]  # first one shown is usually active
            if len(inactive_themes) > 1:
                findings.append(Finding(
                    severity="low",
                    title=f"{len(inactive_themes)} inactive theme(s) installed",
                    evidence="Inactive themes still ship PHP that PHP-FPM will execute if requested.",
                    remediation="Delete every theme you're not using. Keep at most one fallback (e.g. twentytwentyfive).",
                    url=base + "/wp-admin/themes.php",
                ))
        except httpx.HTTPError:
            pass

        # ---- 5. Site Health ----
        step("admin: /wp-admin/site-health.php critical issues...")
        try:
            r = await auth.get(base + "/wp-admin/site-health.php")
            text = r.text or ""
            if "site-health-issues-section-critical" in text:
                crit_count = text.count('class="site-health-issue-critical"') or text.count("site-health-critical")
                if crit_count:
                    findings.append(Finding(
                        severity="high",
                        title=f"WordPress Site Health flags {crit_count} critical issue(s)",
                        evidence="See Tools → Site Health in wp-admin.",
                        remediation="Resolve every Site Health critical issue. They cover PHP version, autoupdate, REST availability, scheduled events.",
                        url=base + "/wp-admin/site-health.php",
                    ))
        except httpx.HTTPError:
            pass

        # ---- 6. Pending updates ----
        step("admin: /wp-admin/update-core.php pending updates...")
        try:
            r = await auth.get(base + "/wp-admin/update-core.php")
            text = r.text or ""
            plugin_updates = len(re.findall(r'plugin-update-tr', text))
            theme_updates = len(re.findall(r'theme-update-tr', text))
            core_pending = ("update-core" in text and "wp_update_core" in text)
            problems = []
            if core_pending:
                problems.append("WordPress core update available")
            if plugin_updates:
                problems.append(f"{plugin_updates} plugin update(s) available")
            if theme_updates:
                problems.append(f"{theme_updates} theme update(s) available")
            if problems:
                findings.append(Finding(
                    severity="high" if core_pending else "medium",
                    title="Pending updates in wp-admin",
                    evidence="\n".join(f"  - {p}" for p in problems),
                    remediation="Apply pending updates. Old core/plugin/theme = #1 cause of WordPress compromise.",
                    url=base + "/wp-admin/update-core.php",
                ))
        except httpx.HTTPError:
            pass

        # ---- 7. Dangerous options ----
        step("admin: /wp-admin/options.php for dangerous flags...")
        try:
            r = await auth.get(base + "/wp-admin/options.php")
            txt = r.text or ""
            problems: list[str] = []
            m = re.search(r'name=["\']default_role["\'][^>]+value=["\']([^"\']+)', txt)
            default_role = m.group(1).lower() if m else ""
            if default_role == "administrator":
                problems.append("default_role = administrator (catastrophic with open registration)")
            users_can_reg = ('name="users_can_register" value="1"' in txt or
                              'name=\'users_can_register\' value=\'1\'' in txt)
            if users_can_reg and default_role in ("administrator", "editor", "author"):
                problems.append(f"users_can_register=ON + default_role={default_role} (high-priv self-registration)")
            blog_public = re.search(r'name=["\']blog_public["\'][^>]+value=["\']0["\']\s+checked', txt)
            if blog_public:
                problems.append("blog_public = 0 (search engines blocked — informational, may be intentional)")
            if problems:
                findings.append(Finding(
                    severity="high",
                    title="Dangerous WordPress option(s)",
                    evidence="\n".join(f"  - {p}" for p in problems),
                    remediation=("Set default_role to 'subscriber'. Disable user registration unless you "
                                  "actually need it. Audit every Settings page after install."),
                    url=base + "/wp-admin/options-general.php",
                ))
        except httpx.HTTPError:
            pass

    finally:
        await auth.aclose()

    if not findings or all(f.severity == "info" for f in findings):
        findings.append(Finding(
            severity="info",
            title="Authenticated scan completed with no critical issues",
            evidence=f"Logged in via {auth_method} and inspected users, plugins, themes, options, Site Health, updates.",
            remediation="No action needed.",
            url=ctx["target"],
        ))
    return findings


def _companion_findings(diag: dict, base: str) -> list[Finding]:
    """Convert the companion-plugin diagnostics payload into findings."""
    out: list[Finding] = []
    core = diag.get("core") or {}
    if core.get("version"):
        out.append(Finding(
            severity="info",
            title=f"Companion: WordPress core v{core['version']}",
            evidence=f"multisite={core.get('multisite')}, language={core.get('language', '?')}",
            remediation="Keep core current.", url=base,
        ))

    plugins = diag.get("plugins") or []
    if plugins:
        active = [p for p in plugins if p.get("active")]
        with_update = [p for p in plugins if p.get("update_available")]
        out.append(Finding(
            severity="info",
            title=f"Companion: {len(plugins)} plugins ({len(active)} active, {len(with_update)} need update)",
            evidence="\n".join(f"  - {p.get('slug')} v{p.get('version')} {'(active)' if p.get('active') else '(inactive)'} {'[UPDATE]' if p.get('update_available') else ''}" for p in plugins[:30]),
            remediation="Apply updates; delete inactive plugins.",
            url=base + "/wp-admin/plugins.php",
        ))
    users = diag.get("users") or []
    no_2fa = [u for u in users if u.get("roles") and "administrator" in u.get("roles", []) and not u.get("2fa_enabled")]
    if no_2fa:
        out.append(Finding(
            severity="high",
            title=f"{len(no_2fa)} administrator(s) without 2FA",
            evidence="\n".join(f"  - {u.get('login', '?')}" for u in no_2fa[:10]),
            remediation="Enable 2FA on every administrator account. The Two-Factor core-team plugin is the canonical choice.",
            url=base + "/wp-admin/users.php?role=administrator",
        ))
    sh_critical = (diag.get("site_health") or {}).get("critical") or []
    if sh_critical:
        out.append(Finding(
            severity="high",
            title=f"Companion: Site Health critical issues ({len(sh_critical)})",
            evidence="\n".join(f"  - {c.get('label')}: {c.get('description', '')[:200]}" for c in sh_critical[:5]),
            remediation="Resolve every Site Health critical issue.",
            url=base + "/wp-admin/site-health.php",
        ))
    return out
