"""Round-62 bundle — small one-off checks that don't warrant their own file:

#B25 — cookie SameSite=None enforcement
#B30 — WebDAV LOCK/UNLOCK
#B32 — PWA manifest + Service Worker scope audit
#B33 — HTTP/3 + QUIC presence
#B34 — colour-contrast measurement (best-effort sample of the home CSS)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urljoin
from ..http import Client
from ..models import Finding


COLOR_RE = re.compile(r"(?:#[0-9a-fA-F]{3,8}|rgba?\([^)]+\))")
PWA_MANIFEST_RE = re.compile(r'<link\s+[^>]*rel\s*=\s*[\"\']?manifest[\"\']?\s+[^>]*href\s*=\s*[\"\']([^\"\']+)[\"\']', re.IGNORECASE)
SW_REG_RE = re.compile(r"serviceWorker\.register\(\s*[\"\']([^\"\']+)[\"\']", re.IGNORECASE)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    home = await client.get("/")
    if home is None:
        return [Finding(severity="info", title="SRI/PWA misc — no response",
                        evidence="", remediation="No action.", url=target)]
    headers = home.headers or {}
    body = (home.text or "")[:200_000]

    # ---- #B25 cookie SameSite ----
    sc = headers.get("Set-Cookie", "")
    if sc:
        cookies = re.split(r",\s*(?=[A-Za-z_][A-Za-z_0-9-]*=)", sc)
        offenders: list[str] = []
        for c in cookies:
            ll = c.lower()
            if "samesite=none" in ll and "secure" not in ll:
                name = c.split("=", 1)[0].strip()
                offenders.append(name)
        if offenders:
            findings.append(Finding(
                severity="high",
                title=f"SameSite=None cookie(s) missing Secure flag ({len(offenders)})",
                evidence="Cookies: " + ", ".join(offenders[:10]),
                remediation=("`SameSite=None` REQUIRES `Secure`. Without it, modern browsers (Chrome 80+) "
                              "ignore the cookie entirely AND log a console warning. Set both flags or "
                              "switch to `SameSite=Lax`."),
                url=target,
            ))

    # ---- #B30 WebDAV LOCK / UNLOCK ----
    step("WebDAV LOCK probe...")
    try:
        r = await client.request("OPTIONS", "/")
        if r is not None and r.headers:
            allow = (r.headers.get("Allow", "") + " " + r.headers.get("DAV", "")).upper()
            if any(m in allow for m in ("LOCK", "UNLOCK", "PROPFIND", "MKCOL")):
                findings.append(Finding(
                    severity="medium",
                    title="WebDAV methods advertised in OPTIONS",
                    evidence=f"Allow: {r.headers.get('Allow', '')[:120]}\nDAV: {r.headers.get('DAV', '')[:120]}",
                    remediation=("WebDAV is rarely needed on a public WP. Disable in nginx/Apache config "
                                  "(`Dav Off` in Apache, or strip the `dav_methods` directive in nginx)."),
                    url=target,
                ))
    except (ValueError, AttributeError):
        pass

    # ---- #B32 PWA manifest + SW ----
    manifest_m = PWA_MANIFEST_RE.search(body)
    sw_m = SW_REG_RE.search(body)
    if manifest_m or sw_m:
        details = []
        if manifest_m:
            manifest_url = manifest_m.group(1)
            details.append(f"manifest: {manifest_url}")
            # Fetch + sanity check
            try:
                rm = await client.get(urljoin(target + "/", manifest_url))
                if rm is not None and rm.status_code == 200 and rm.text:
                    if '"start_url"' not in rm.text:
                        findings.append(Finding(
                            severity="low",
                            title="PWA manifest missing start_url",
                            evidence=f"Manifest at {manifest_url} has no start_url field.",
                            remediation="Add `start_url` to ensure PWA launch behaviour is deterministic.",
                            url=target + manifest_url,
                        ))
            except (ValueError, AttributeError):
                pass
        if sw_m:
            sw_url = sw_m.group(1)
            details.append(f"service-worker: {sw_url}")
            if not sw_url.startswith("/") and not sw_url.startswith("http"):
                findings.append(Finding(
                    severity="medium",
                    title="Service Worker registered with relative path (scope ambiguity)",
                    evidence=f"navigator.serviceWorker.register('{sw_url}') — scope unclear.",
                    remediation="Register with an absolute path + explicit scope option to avoid SW hijacking on subpaths.",
                    url=target,
                ))
        findings.append(Finding(
            severity="info",
            title="PWA / Service Worker detected",
            evidence="\n".join(details),
            remediation="PWAs persistently cache assets. Audit SW for cache-poisoning + ensure unregister-on-uninstall path.",
            url=target,
        ))

    # ---- #B33 HTTP/3 + QUIC ----
    alt_svc = headers.get("alt-svc", "") or headers.get("Alt-Svc", "")
    if alt_svc and "h3" in alt_svc.lower():
        findings.append(Finding(
            severity="info",
            title="HTTP/3 (QUIC) advertised via Alt-Svc",
            evidence=f"alt-svc: {alt_svc[:200]}",
            remediation="No action — HTTP/3 is good. Confirm fallback to HTTP/2 if QUIC is blocked.",
            url=target,
        ))

    # ---- #B34 contrast measurement (best-effort) ----
    # Pull all <style> blocks + first stylesheet; sample foreground/background pairs
    style_blocks = re.findall(r"<style\b[^>]*>(.*?)</style>", body, re.IGNORECASE | re.DOTALL)
    inline_css = "\n".join(style_blocks)
    bg_colors = COLOR_RE.findall(inline_css)
    if len(bg_colors) < 4:
        # Try external stylesheet
        css_link = re.search(r'<link\s+[^>]*rel\s*=\s*[\"\']?stylesheet[\"\']?\s+[^>]*href\s*=\s*[\"\']([^\"\']+)[\"\']', body, re.IGNORECASE)
        if css_link:
            try:
                rcss = await client.get(urljoin(target + "/", css_link.group(1)))
                if rcss is not None and rcss.status_code == 200 and rcss.text:
                    bg_colors.extend(COLOR_RE.findall(rcss.text[:200_000]))
            except (ValueError, AttributeError):
                pass
    if bg_colors:
        findings.append(Finding(
            severity="info",
            title=f"Colour palette analyzed ({len(set(bg_colors))} unique colours)",
            evidence=(f"For full WCAG AA / AAA contrast measurement, run an in-browser tool "
                       f"(Lighthouse, axe-core, WAVE). This check only counts the palette: "
                       f"{', '.join(sorted(set(bg_colors))[:10])}"),
            remediation="WCAG 2.2 requires 4.5:1 for normal text, 3:1 for large text. Use a browser-based contrast checker for accurate measurement.",
            url=target,
        ))

    return findings or [Finding(severity="info", title="SRI/PWA misc — clean",
                                 evidence="", remediation="No action.", url=target)]
