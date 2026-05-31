"""F15 (v2.8.1) — REST-only admin / wp-admin lockdown probe.

Best practice for headless WP installs: block /wp-admin from the
public internet entirely; admins SSH-tunnel or VPN. We flag if
/wp-admin/ is reachable AND the site exposes any signal it's a
REST-only install (no theme renders on /, JSON API works).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F15: probing /wp-admin reachability vs REST-only signals")
    admin = await client.get("/wp-admin/")
    rest_root = await client.get("/wp-json/")
    home = await client.get("/")
    if admin is None or rest_root is None or home is None:
        return []
    rest_ok = rest_root.status_code == 200
    admin_open = admin.status_code in (200, 302) and \
        ("wp-login.php" in (admin.text or "") or
          "wp-admin" in (admin.headers.get("location", "") or ""))
    headless_signal = (len(home.text or "") < 5000 or
                        ("wp-content/themes" not in (home.text or "")))
    if rest_ok and admin_open and headless_signal:
        return [Finding(severity="medium",
                         title="F15: REST-only / headless site has public /wp-admin",
                         evidence=(
                             "REST API reachable, homepage shows headless markers, "
                             "yet /wp-admin/ is publicly accessible. Reduces attack-"
                             "surface mitigation that headless was supposed to offer."),
                         remediation=(
                             "Block /wp-admin and /wp-login.php at nginx/Cloudflare:\n"
                             "  location ~ ^/wp-(admin|login\\.php) { allow VPN_IPS; deny all; }\n"
                             "REST API stays public for headless front-end consumption."),
                         url=ctx["target"])]
    return []
