from .waf import check as waf
from .core_version import check as core_version
from .plugins import check as plugins
from .themes import check as themes
from .users import check as users
from .exposed_files import check as exposed_files
from .login import check as login
from .login_throttle import check as login_throttle
from .login_throttle_deep import check as login_throttle_deep
from .tls_headers import check as tls_headers
from .csp import check as csp
from .directory_listing import check as directory_listing
from .debug_leaks import check as debug_leaks
from .robots_sitemap import check as robots_sitemap
from .cookies import check as cookies
from .http_methods import check as http_methods
from .subdomains import check as subdomains
from .hibp import check as hibp
from .rest_api import check as rest_api
from .cors import check as cors
from .js_libraries import check as js_libraries
from .secret_leak import check as secret_leak
from .wpgraphql import check as wpgraphql
from .ajax_surface import check as ajax_surface
from .backup_exposure import check as backup_exposure
from .core_tampering import check as core_tampering
from .csrf_nonce import check as csrf_nonce
from .app_passwords import check as app_passwords
from .mixed_content import check as mixed_content
from .tls_deep import check as tls_deep
from .multisite import check as multisite
from .webhooks import check as webhooks
from .sendmail_injection import check as sendmail_injection
from .cache_headers import check as cache_headers
from .xmlrpc_deep import check as xmlrpc_deep
from .redirect_chain import check as redirect_chain
from .error_pages import check as error_pages
from .xss_dom_sinks import check as xss_dom_sinks
from .nonce_freshness import check as nonce_freshness
from .security_txt import check as security_txt
from .favicon_fingerprint import check as favicon_fingerprint
from .admin_ajax_brute_surface import check as admin_ajax_brute_surface
from .dns_security import check as dns_security
from .source_maps import check as source_maps
from .js_supply_chain import check as js_supply_chain
from .server_timing import check as server_timing
from .wp_rest_methods import check as wp_rest_methods
# New 20 (passive part)
from .gdpr_dsr import check as gdpr_dsr
from .wp_engine_misconfig import check as wp_engine_misconfig
from .oauth_redirect import check as oauth_redirect
from .cache_poisoning import check as cache_poisoning
from .upload_path_predictable import check as upload_path_predictable
from .http2_settings import check as http2_settings
from .favicon_hash import check as favicon_hash
from .a11y_lite import check as a11y_lite
from .smuggling_probe import check as smuggling_probe
from .tls_protocol_audit import check as tls_protocol_audit
from .cookie_consent import check as cookie_consent
from .websocket_audit import check as websocket_audit
from .woocommerce_audit import check as woocommerce_audit
from .graphql_dos import check as graphql_dos
# Round-Q 24-feature batch
from .well_known import check as well_known
from .login_timing import check as login_timing
from .sitemap_cve_probe import check as sitemap_cve_probe
# Round-54 (waves 1-9): new checks
from .webdav import check as webdav
from .dev_params import check as dev_params
from .abuseipdb_lookup import check as abuseipdb_lookup
from .jwt_audit import check as jwt_audit
from .ssti import check as ssti
from .nosql_injection import check as nosql_injection
from .s3_bucket_discovery import check as s3_bucket_discovery
from .github_leak_search import check as github_leak_search
from .path_bypass import check as path_bypass
from .race_condition import check as race_condition
from .waf_ruleset import check as waf_ruleset
from .oauth_oidc import check as oauth_oidc
from .saml_xsw import check as saml_xsw
from .dom_xss_headless import check as dom_xss_headless
# Round-55 (waves A-H): 10 new checks
from .cloud_metadata_ssrf import check as cloud_metadata_ssrf
from .dns_rebinding import check as dns_rebinding
from .http3_fingerprint import check as http3_fingerprint
from .session_fixation import check as session_fixation
from .csrf_entropy import check as csrf_entropy
from .hpp import check as hpp
from .backup_file_fuzz import check as backup_file_fuzz
from .hostname_collision import check as hostname_collision
from .plugin_route_fuzz import check as plugin_route_fuzz
from .header_smuggling_case import check as header_smuggling_case
# Round-57 (40 features): new checks
from .timthumb import check as timthumb
from .plugin_hash_fingerprint import check as plugin_hash_fingerprint
from .users_deep import check as users_deep
from .plugin_archive_fuzz import check as plugin_archive_fuzz
from .premium_license_leak import check as premium_license_leak
from .xmlrpc_method_brute import check as xmlrpc_method_brute
from .yaml_templates import check as yaml_templates
from .yaml_workflows import check as yaml_workflows
from .dns_templates import check as dns_templates
from .headless_templates import check as headless_templates
from .spider_crawl import check as spider_crawl
from .forced_browse import check as forced_browse
from .websocket_fuzz import check as websocket_fuzz
from .openapi_scanner import check as openapi_scanner
from .mobile_app_endpoints import check as mobile_app_endpoints
from .host_recon import check as host_recon

# CVE matching (uses the Wordfence DB; runs whenever DB is present)
from .core_cves import check as core_cves
from .plugin_cves import check as plugin_cves
from .theme_cves import check as theme_cves

# Aggressive (active payloads) — opt-in
from .sqli import check as sqli
from .xss_reflected import check as xss_reflected
from .open_redirect import check as open_redirect
from .ssrf import check as ssrf
from .path_traversal import check as path_traversal
from .file_upload import check as file_upload
from .default_creds import check as default_creds
# Aggressive new ones
from .prototype_pollution import check as prototype_pollution
from .graphql_field_dos import check as graphql_field_dos
from .csv_export_csp import check as csv_export_csp
from .waf_bypass_probe import check as waf_bypass_probe
from .xxe_upload import check as xxe_upload

# Authenticated — only when creds are provided
from .authenticated import check as authenticated

# (check_id, display_name, fn, aggressive)
# WAF runs first so downstream checks can read ctx['shared']['waf'].
# Plugin enumeration must run before CVE matching for plugins.
ALL_CHECKS = [
    ("waf",                "WAF / CDN detection",        waf,                False),
    ("core_version",       "WordPress core version",     core_version,       False),
    ("plugins",            "Plugin enumeration",         plugins,            False),
    ("themes",             "Theme enumeration",          themes,             False),
    ("users",              "User enumeration",           users,              False),
    ("exposed_files",      "Exposed files",              exposed_files,      False),
    ("login",              "Login surface",              login,              False),
    ("login_throttle",     "Login rate-limiting test",   login_throttle,     False),
    ("tls_headers",        "TLS & security headers",     tls_headers,        False),
    ("csp",                "CSP deep analysis",          csp,                False),
    ("cookies",            "Cookie hardening",           cookies,            False),
    ("http_methods",       "HTTP method enumeration",    http_methods,       False),
    ("directory_listing",  "Directory listing",          directory_listing,  False),
    ("debug_leaks",        "Debug & info leaks",         debug_leaks,        False),
    ("robots_sitemap",     "robots.txt / sitemap audit", robots_sitemap,     False),
    ("subdomains",         "Subdomain discovery",        subdomains,         False),
    ("rest_api",           "WP REST API surface audit",  rest_api,           False),
    ("cors",               "CORS misconfiguration",      cors,               False),
    ("js_libraries",       "JS library version audit",   js_libraries,       False),
    ("secret_leak",        "Accidental API-key leak scan", secret_leak,      False),
    ("wpgraphql",          "WPGraphQL endpoint audit",   wpgraphql,          False),
    ("backup_exposure",    "Backup-plugin file exposure",backup_exposure,    False),
    ("csrf_nonce",         "CSRF / nonce form audit",    csrf_nonce,         False),
    ("app_passwords",      "Application Passwords audit",app_passwords,      False),
    ("mixed_content",      "Mixed-content (HTTP-in-HTTPS) audit", mixed_content, False),
    ("tls_deep",           "Deep TLS audit",             tls_deep,           False),
    ("multisite",          "WordPress Multisite audit",  multisite,          False),
    ("webhooks",           "Webhook endpoint discovery", webhooks,           False),
    ("cache_headers",      "Cache-header audit",         cache_headers,      False),
    ("xmlrpc_deep",        "XML-RPC method enumeration", xmlrpc_deep,        False),
    ("redirect_chain",     "Redirect chain analysis",    redirect_chain,     False),
    ("error_pages",        "Error-page fingerprinting",  error_pages,        False),
    ("xss_dom_sinks",      "DOM-XSS source/sink scan",   xss_dom_sinks,      False),
    ("nonce_freshness",    "WP nonce freshness audit",   nonce_freshness,    False),
    ("security_txt",       "security.txt (RFC 9116) audit", security_txt,    False),
    ("favicon_fingerprint","Favicon fingerprint",        favicon_fingerprint,False),
    ("admin_ajax_brute_surface","admin-ajax throttle probe", admin_ajax_brute_surface, False),
    ("dns_security",       "DNS security (SPF/DMARC/DKIM)", dns_security,    False),
    ("source_maps",        "Source-map exposure",        source_maps,        False),
    ("js_supply_chain",    "External JS supply-chain audit", js_supply_chain,False),
    ("server_timing",      "Server-Timing / debug headers", server_timing,   False),
    ("wp_rest_methods",    "REST method enumeration",    wp_rest_methods,    False),
    # ---- 13 new passive checks (round Q) ----
    ("gdpr_dsr",           "GDPR Data-Subject-Request audit", gdpr_dsr,      False),
    ("wp_engine_misconfig","WP Engine private-path leaks",  wp_engine_misconfig, False),
    ("oauth_redirect",     "OAuth / login redirect-URI",  oauth_redirect,    False),
    ("cache_poisoning",    "Web-cache poisoning probe",   cache_poisoning,   False),
    ("upload_path_predictable", "Predictable upload paths", upload_path_predictable, False),
    ("http2_settings",     "HTTP/2 fingerprint + EOL backend", http2_settings, False),
    ("favicon_hash",       "Favicon fingerprint hash (Shodan)", favicon_hash, False),
    ("a11y_lite",          "Accessibility smoke check",   a11y_lite,         False),
    ("smuggling_probe",    "HTTP request-smuggling indicators", smuggling_probe, False),
    ("tls_protocol_audit", "Deep TLS protocol + cipher + cert audit", tls_protocol_audit, False),
    ("cookie_consent",     "GDPR/ePrivacy cookie-consent audit", cookie_consent, False),
    ("websocket_audit",    "WebSocket upgrade + origin audit", websocket_audit, False),
    ("woocommerce_audit",  "WooCommerce REST + legacy-API audit", woocommerce_audit, False),
    ("graphql_dos",        "GraphQL alias-amplification DoS", graphql_dos,    False),
    # ---- Round-Q passive additions ----
    ("well_known",         "/.well-known/ resource enumeration", well_known, False),
    ("login_timing",       "Login timing side-channel (user enum)", login_timing, False),
    ("sitemap_cve_probe",  "Sitemap-driven CVE pattern probe", sitemap_cve_probe, False),
    # ---- Round-54 passive checks (waves 1-4) ----
    ("webdav",             "WebDAV / OPTIONS enumeration", webdav,                False),
    ("dev_params",         "Beta/test/debug query parameters", dev_params,        False),
    ("abuseipdb_lookup",   "AbuseIPDB reputation (opt-in)", abuseipdb_lookup,      False),
    ("waf_ruleset",        "WAF rule-set identification",  waf_ruleset,           False),
    ("oauth_oidc",         "OAuth2 / OIDC discovery audit", oauth_oidc,           False),
    ("saml_xsw",           "SAML / XSW endpoint discovery", saml_xsw,             False),
    ("s3_bucket_discovery","S3 bucket discovery + public-ACL", s3_bucket_discovery, False),
    ("github_leak_search", "GitHub leaked-token search (opt-in)", github_leak_search, False),
    ("jwt_audit",          "JWT audit (alg=none + weak HS256)", jwt_audit,        False),
    # ---- CVE matching ----
    ("hibp",               "HaveIBeenPwned lookup",      hibp,               False),
    ("core_cves",          "Core CVE matching",          core_cves,          False),
    ("plugin_cves",        "Plugin CVE matching",        plugin_cves,        False),
    ("theme_cves",         "Theme CVE matching",         theme_cves,         False),
    # ---- Aggressive ----
    ("sqli",               "SQL injection probes",       sqli,               True),
    ("xss_reflected",      "Reflected XSS probes",       xss_reflected,      True),
    ("open_redirect",      "Open-redirect probes",       open_redirect,      True),
    ("ssrf",               "SSRF probes",                ssrf,               True),
    ("path_traversal",     "Path traversal probes",      path_traversal,     True),
    ("file_upload",        "Upload-endpoint probes",     file_upload,        True),
    ("default_creds",      "Default credentials probe",  default_creds,      True),
    ("ajax_surface",       "admin-ajax action surface",  ajax_surface,       True),
    ("core_tampering",     "Core file tampering check",  core_tampering,     True),
    ("sendmail_injection", "Email header injection probe", sendmail_injection, True),
    # ---- 4 new aggressive checks (round Q) ----
    ("prototype_pollution","Prototype-pollution reflection probe", prototype_pollution, True),
    ("graphql_field_dos",  "GraphQL query-depth DoS probe", graphql_field_dos, True),
    ("csv_export_csp",     "CSV-export formula-injection probe", csv_export_csp, True),
    ("waf_bypass_probe",   "WAF bypass/passthrough probe", waf_bypass_probe,  True),
    ("xxe_upload",         "XXE via SVG upload probe",   xxe_upload,         True),
    # ---- Round-54 aggressive checks (waves 2 + 5) ----
    ("ssti",               "Server-side template injection probe", ssti,     True),
    ("nosql_injection",    "NoSQL operator injection probe", nosql_injection, True),
    ("path_bypass",        "Path-normalisation bypass probe", path_bypass,   True),
    ("race_condition",     "Race-condition probe (parallel POSTs)", race_condition, True),
    ("dom_xss_headless",   "Headless DOM-XSS (Playwright, opt-in)", dom_xss_headless, True),
    # ---- Round-55 passive checks ----
    ("http3_fingerprint",  "HTTP/3 + QUIC fingerprint",  http3_fingerprint,    False),
    ("session_fixation",   "Session-fixation precondition probe", session_fixation, False),
    ("csrf_entropy",       "CSRF nonce entropy sampler", csrf_entropy,         False),
    ("backup_file_fuzz",   "Backup-file long-tail fuzzer", backup_file_fuzz,    False),
    ("hostname_collision", "Apex vs www hostname collision", hostname_collision, False),
    ("plugin_route_fuzz",  "Plugin REST-route fuzzer",   plugin_route_fuzz,     False),
    # ---- Round-55 aggressive checks ----
    ("hpp",                "HTTP Parameter Pollution probe", hpp,              True),
    ("header_smuggling_case","Header smuggling via case sensitivity", header_smuggling_case, True),
    ("cloud_metadata_ssrf","Cloud-metadata SSRF chain (needs SSRF candidate)", cloud_metadata_ssrf, True),
    ("dns_rebinding",      "DNS-rebinding SSRF probe",   dns_rebinding,        True),
    # ---- Round-57 passive checks (wpscan / nuclei / ZAP parity) ----
    ("timthumb",           "timthumb.php CVE detection (#1)", timthumb,         False),
    ("plugin_hash_fingerprint", "Plugin file-hash fingerprint (#2)", plugin_hash_fingerprint, False),
    ("users_deep",         "Deep user enumeration — 10 sources (#5)", users_deep, False),
    ("premium_license_leak","Premium plugin license-key leak scan (#7)", premium_license_leak, False),
    ("xmlrpc_method_brute","XML-RPC hidden-method brute-force (#8)", xmlrpc_method_brute, False),
    ("yaml_templates",     "YAML templates (nuclei-style) (#9)", yaml_templates, False),
    ("yaml_workflows",     "YAML workflow chaining (#11)", yaml_workflows, False),
    ("dns_templates",      "DNS templates (#13)", dns_templates, False),
    ("spider_crawl",       "Spider — recursive link crawler (#18)", spider_crawl, False),
    ("forced_browse",      "Forced-browse hidden-path discovery (#21)", forced_browse, False),
    ("openapi_scanner",    "OpenAPI / Swagger endpoint scanner (#26)", openapi_scanner, False),
    ("mobile_app_endpoints","Mobile-app association discovery (#38)", mobile_app_endpoints, False),
    ("host_recon",         "Host port recon — Docker/Redis/k8s/etc. (#40)", host_recon, False),
    # ---- Round-57 aggressive checks ----
    ("plugin_archive_fuzz","Plugin source-archive fuzz (#6)", plugin_archive_fuzz, True),
    ("headless_templates", "Headless DOM templates (Playwright) (#14)", headless_templates, True),
    ("websocket_fuzz",     "WebSocket frame fuzzer (#23)", websocket_fuzz, True),
    # Deep throttle runs last (~20 min) so all fast checks complete first — risk score
    # and findings appear in ~1-2 min instead of after the throttle test finishes.
    # Self-skips unless ctx["deep_throttle"] is set, so position is harmless when off.
    ("login_throttle_deep","Deep throttle mapping (opt-in, 20 min)", login_throttle_deep, False),
    ("authenticated",      "Authenticated scan",         authenticated,      False),  # gated by creds
]


def _load_disabled_checks() -> set[str]:
    """C1: read the user's persisted check-disable list.

    Lazy + cached-by-call so the GUI's disable grid can flip values at runtime
    and the next scan picks them up without a restart.
    """
    try:
        import json
        from pathlib import Path
        import os
        home = os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan")
        f = Path(home) / "disabled_checks.json"
        if not f.exists():
            return set()
        return set(json.loads(f.read_text(encoding="utf-8")) or [])
    except (OSError, ValueError, Exception):  # noqa: BLE001
        return set()


_CUSTOM_CHECKS_LOADED = False


def _load_custom_checks() -> None:
    """E1: discover and load user-supplied check modules from ~/.wpsecscan/plugins/*.py.

    Each plugin module exposes:
      CHECK_ID:  str (required, must be unique)
      CHECK_NAME: str (required)
      IS_AGGRESSIVE: bool (default False)
      async def check(client, ctx) -> list[Finding]  (required)

    Loaded plugins are appended to ALL_CHECKS the first time this is called.
    Safe-by-default: errors in one plugin don't block others or the built-in checks.
    """
    global _CUSTOM_CHECKS_LOADED
    if _CUSTOM_CHECKS_LOADED:
        return
    _CUSTOM_CHECKS_LOADED = True
    try:
        import importlib.util
        import os
        from pathlib import Path
        home = os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan")
        plugins_dir = Path(home) / "plugins"
        if not plugins_dir.exists():
            return
        existing_ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
        for py_file in sorted(plugins_dir.glob("*.py")):
            try:
                spec = importlib.util.spec_from_file_location(
                    f"_wpsec_user_plugin_{py_file.stem}", py_file
                )
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                cid = getattr(mod, "CHECK_ID", None)
                cname = getattr(mod, "CHECK_NAME", None)
                fn = getattr(mod, "check", None)
                agg = bool(getattr(mod, "IS_AGGRESSIVE", False))
                if not cid or not cname or fn is None:
                    continue
                if cid in existing_ids:
                    # Don't let a user plugin shadow a built-in check
                    continue
                ALL_CHECKS.append((cid, cname, fn, agg))
                existing_ids.add(cid)
            except Exception:  # noqa: BLE001
                # One broken plugin shouldn't break the whole scanner
                continue
    except Exception:  # noqa: BLE001
        pass


# Discover user plugins at import time (one-shot).
_load_custom_checks()


def select_checks(aggressive: bool, authenticated_enabled: bool = False):
    """Return active checks given the mode flags."""
    disabled = _load_disabled_checks()
    out = []
    for cid, cname, fn, agg in ALL_CHECKS:
        if cid in disabled:
            continue
        if cid == "authenticated" and not authenticated_enabled:
            continue
        if agg and not aggressive:
            continue
        out.append((cid, cname, fn))
    return out


# Backwards-compat alias used by older callers — passive only, no auth
CHECKS = [(cid, cname, fn) for cid, cname, fn, agg in ALL_CHECKS if not agg and cid != "authenticated"]
