"""Round-59 #7, #9-15 — Plugin-ecosystem audit (search, SEO, backup, SMTP,
caching, CDN plugin, security plugin, live-chat).

Each plugin family has a canonical "leaked config/credential" path. We
fingerprint then probe that one path. False-positive rate is low —
backup-plugin SQL dumps and SMTP API keys in cleartext are the actual
worst-case secrets-in-the-web-root pattern.

#7  Search:   Relevanssi, SearchWP, Ajax Search Pro
#9  SEO:      Yoast, RankMath, AIOSEO, SEOPress — sitemap config dumps
#10 Backup:   UpdraftPlus, BackWPup, WPVivid, Duplicator — SQL/dump exposure
#11 SMTP:     WP Mail SMTP, Post SMTP, Easy WP SMTP — API key leak
#12 Caching:  W3 Total Cache, WP Super Cache, WP Rocket, Cache Enabler
#13 CDN:      CDN Enabler, Photon, Smush CDN
#14 Security: Wordfence, Sucuri, iThemes Security, AIOWPS — log paths
#15 Chat:     Tawk, LiveChat, Crisp, Tidio, Drift
"""
from __future__ import annotations

import re
from ..http import Client
from ..models import Finding


VERSION_RE = re.compile(r"Version:\s*([\d.]+)", re.IGNORECASE)


# (category, name, plugin-path, follow-up probes [(path, severity, finding)])
PLUGINS = [
    # ---- #7 Search ----
    ("search", "Relevanssi",       "/wp-content/plugins/relevanssi/relevanssi.php", []),
    ("search", "SearchWP",         "/wp-content/plugins/searchwp/searchwp.php", []),
    ("search", "Ajax Search Pro",  "/wp-content/plugins/ajax-search-pro/ajax-search-pro.php", []),

    # ---- #9 SEO ----
    ("seo", "Yoast",     "/wp-content/plugins/wordpress-seo/wp-seo.php",
        [("/wp-sitemap.xml", "info", "Yoast sitemap exposed (intentional, but check robots disallow)")]),
    ("seo", "RankMath",  "/wp-content/plugins/seo-by-rank-math/rank-math.php",
        [("/sitemap_index.xml", "info", "RankMath sitemap exposed")]),
    ("seo", "AIOSEO",    "/wp-content/plugins/all-in-one-seo-pack/all_in_one_seo_pack.php",
        [("/sitemap.xml", "info", "AIOSEO sitemap exposed")]),
    ("seo", "SEOPress",  "/wp-content/plugins/wp-seopress/seopress.php", []),

    # ---- #10 Backup ----
    ("backup", "UpdraftPlus",  "/wp-content/plugins/updraftplus/updraftplus.php",
        [("/wp-content/updraft/", "high", "UpdraftPlus backup directory listable — contains DB dumps + files")]),
    ("backup", "BackWPup",     "/wp-content/plugins/backwpup/backwpup.php",
        [("/wp-content/uploads/backwpup-logs/", "high", "BackWPup logs directory listable")]),
    ("backup", "WPVivid",      "/wp-content/plugins/wpvivid-backuprestore/wpvivid-backuprestore.php",
        [("/wp-content/wpvividbackups/", "high", "WPVivid backup directory listable")]),
    ("backup", "Duplicator",   "/wp-content/plugins/duplicator/duplicator.php",
        [("/wp-content/backups-dup-lite/", "critical", "Duplicator backups + installer.php exposed — full site dump"),
         ("/installer.php", "critical", "Duplicator installer.php in webroot — RCE on un-removed dev install"),
         ("/installer-backup.php", "critical", "Duplicator installer-backup.php in webroot")]),

    # ---- #11 SMTP ----
    ("smtp", "WP Mail SMTP",   "/wp-content/plugins/wp-mail-smtp/wp_mail_smtp.php", []),
    ("smtp", "Post SMTP",      "/wp-content/plugins/post-smtp/postman-smtp.php",
        [("/wp-content/plugins/post-smtp/logs/", "medium", "Post SMTP log directory listable")]),
    ("smtp", "Easy WP SMTP",   "/wp-content/plugins/easy-wp-smtp/easy-wp-smtp.php",
        [("/wp-content/plugins/easy-wp-smtp/easy-wp-smtp_debug_log.txt", "high",
          "Easy WP SMTP debug log in webroot — historically contained SMTP creds")]),

    # ---- #12 Caching ----
    ("cache", "W3 Total Cache", "/wp-content/plugins/w3-total-cache/w3-total-cache.php",
        [("/wp-content/w3tc-config/master.php", "critical", "W3TC master config exposed — contains keys/secrets"),
         ("/wp-content/cache/page_enhanced/", "low", "W3TC page cache directory listable")]),
    ("cache", "WP Super Cache","/wp-content/plugins/wp-super-cache/wp-cache.php",
        [("/wp-content/cache/supercache/", "low", "WP Super Cache directory listable")]),
    ("cache", "WP Rocket",     "/wp-content/plugins/wp-rocket/wp-rocket.php", []),
    ("cache", "Cache Enabler", "/wp-content/plugins/cache-enabler/cache-enabler.php", []),

    # ---- #13 CDN plugin ----
    ("cdn", "CDN Enabler",     "/wp-content/plugins/cdn-enabler/cdn-enabler.php", []),
    ("cdn", "Smush CDN",       "/wp-content/plugins/wp-smushit/wp-smush.php", []),

    # ---- #14 Security plugin ----
    ("sec", "Wordfence",       "/wp-content/plugins/wordfence/wordfence.php",
        [("/wp-content/wflogs/", "medium", "Wordfence logs directory listable — may expose request IPs/scan history")]),
    ("sec", "Sucuri",          "/wp-content/plugins/sucuri-scanner/sucuri.php",
        [("/wp-content/uploads/sucuri/", "medium", "Sucuri logs directory listable")]),
    ("sec", "iThemes Security","/wp-content/plugins/better-wp-security/better-wp-security.php", []),
    ("sec", "AIOWPS",          "/wp-content/plugins/all-in-one-wp-security-and-firewall/wp-security.php",
        [("/wp-content/aiowps_backups/", "high", "AIOWPS DB backup directory listable")]),

    # ---- #15 Live chat ----
    ("chat", "Tawk.to",        "/wp-content/plugins/tawkto-live-chat/tawkto.php", []),
    ("chat", "LiveChat",       "/wp-content/plugins/wp-live-chat-support/wp-live-chat-support.php", []),
    ("chat", "Crisp",          "/wp-content/plugins/crisp/crisp.php", []),
    ("chat", "Tidio",          "/wp-content/plugins/tidio-live-chat/tidio-live-chat.php", []),
    ("chat", "Drift",          "/wp-content/plugins/drift/drift.php", []),
]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    target = ctx["target"].rstrip("/")

    def _full(p: str) -> str:
        return target + p

    detected_by_cat: dict[str, list[tuple[str, str | None]]] = {}

    for category, name, plugin_path, probes in PLUGINS:
        step(f"{category} plugin probe {name}...")
        r = await client.get(plugin_path)
        if r is None or r.status_code != 200 or not r.text:
            continue
        m = VERSION_RE.search(r.text)
        version = m.group(1) if m else None
        detected_by_cat.setdefault(category, []).append((name, version))

        # follow-up probes
        for probe_path, severity, message in probes:
            rr = await client.get(probe_path)
            if rr is None or rr.status_code != 200:
                continue
            # Detect directory-listing OR plain-text file with content
            body = rr.text or ""
            if probe_path.endswith("/"):
                if "Index of" not in body and "<a href" not in body.lower():
                    continue
            elif not body:
                continue
            findings.append(Finding(
                severity=severity,
                title=f"{name}: {message}",
                evidence=f"GET {probe_path} -> {rr.status_code} ({len(body)} bytes).",
                remediation=(
                    f"Add an empty index.html in `{probe_path}` and disable directory "
                    f"listing in nginx/.htaccess. Move {name}'s data outside the web root if possible."
                ),
                url=_full(probe_path),
            ))

    # Emit one info finding per category with detected plugins
    for cat, items in detected_by_cat.items():
        label = {
            "search": "Search plugin(s)",
            "seo": "SEO plugin(s)",
            "backup": "Backup plugin(s)",
            "smtp": "SMTP plugin(s)",
            "cache": "Caching plugin(s)",
            "cdn": "CDN plugin(s)",
            "sec": "Security plugin(s)",
            "chat": "Live-chat plugin(s)",
        }.get(cat, cat)
        findings.append(Finding(
            severity="info",
            title=f"{label} detected: {len(items)}",
            evidence="\n".join(f"  - {n} {v or '?'}" for n, v in items),
            remediation=f"Each {label.lower()} adds attack surface. Keep on the latest minor and audit its REST/AJAX surface.",
            url=target,
        ))

    if not findings:
        return [Finding(severity="info", title="Plugin-ecosystem audit — none of the tracked plugins detected",
                        evidence=f"Probed {len(PLUGINS)} plugins across 8 ecosystems.",
                        remediation="No action.", url=target)]
    return findings
