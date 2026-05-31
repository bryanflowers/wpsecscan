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
from .a11y_lite import check as a11y_lite
from .smuggling_probe import check as smuggling_probe
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
from .referenced_buckets import check as referenced_buckets
from .cloudflare_origin_leak import check as cloudflare_origin_leak
from .crlf_location_injection import check as crlf_location_injection
from .host_header_validation import check as host_header_validation
from .woocommerce_storefront import check as woocommerce_storefront
from .page_builder_cve import check as page_builder_cve
from .wp_fork_detection import check as wp_fork_detection
from .tls_modern import check as tls_modern
from .companion_advanced import check as companion_advanced
from .waf_lockout_guard import check as waf_lockout_guard
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
# Round-58 (117 features): new checks
from .gutenberg_blocks import check as gutenberg_blocks
from .wp_cron_dos import check as wp_cron_dos
from .rest_permission_audit import check as rest_permission_audit
from .wp_query_sqli import check as wp_query_sqli
from .wp_salts_age import check as wp_salts_age
from .heartbeat_abuse import check as heartbeat_abuse
from .woocommerce_deep import check as woocommerce_deep
from .plugin_specific_audit import check as plugin_specific_audit
from .hosting_platform_audit import check as hosting_platform_audit
from .origin_ip_discovery import check as origin_ip_discovery
from .upload_bypass_deep import check as upload_bypass_deep
from .misc_injection_audit import check as misc_injection_audit
from .tls_reneg_dos import check as tls_reneg_dos
from .cache_poisoning_v2 import check as cache_poisoning_v2
from .osint_enrich import check as osint_enrich
# Round-59 (111 features): new checks
from .wp_builder_audit import check as wp_builder_audit
from .wp_form_audit import check as wp_form_audit
from .wp_membership_lms_audit import check as wp_membership_lms_audit
from .wp_commerce_alt_audit import check as wp_commerce_alt_audit
from .wp_plugin_ecosystem_audit import check as wp_plugin_ecosystem_audit
from .privacy_inventory import check as privacy_inventory
from .email_security_deep import check as email_security_deep
from .dns_deep import check as dns_deep
from .auth_modernisation import check as auth_modernisation
from .crypto_agility import check as crypto_agility
from .cdn_edge_audit import check as cdn_edge_audit
from .payment_commerce_deep import check as payment_commerce_deep
from .compliance_frameworks import check as compliance_frameworks
from .headless_wp_audit import check as headless_wp_audit
# Round-60 (28 features): new checks
from .wp_multisite_deep import check as wp_multisite_deep
from .honeypot_admin import check as honeypot_admin
from .a11y_deep import check as a11y_deep
from .perf_budget import check as perf_budget
# Round-62 (B21-B38): new checks
from .server_stack_reveal import check as server_stack_reveal
from .waf_brand_deep import check as waf_brand_deep
from .sri_audit import check as sri_audit
from .service_exposure import check as service_exposure
from .js_framework_deep import check as js_framework_deep
from .sri_pwa_misc import check as sri_pwa_misc
from .wp_cli_inject import check as wp_cli_inject

# CVE matching (uses the Wordfence DB; runs whenever DB is present)
from .core_cves import check as core_cves
from .plugin_cves import check as plugin_cves
from .plugin_cemetery import check as plugin_cemetery
from .theme_cves import check as theme_cves

# Audit-extras-v1 (FEAT-001/021/032/035/037/040) — six small detection wins
from .php_eol import check as php_eol
from .permissions_policy import check as permissions_policy
from .heartbeat_frontend import check as heartbeat_frontend
from .users_me_capability_leak import check as users_me_capability_leak
from .rest_link_header import check as rest_link_header
from .csp_report_endpoint import check as csp_report_endpoint
# Audit-extras-v2 (FEAT-004/008/013/023/033/041)
from .wp_cron_disabled import check as wp_cron_disabled
from .rest_fields_dos import check as rest_fields_dos
from .woocommerce_order_idor import check as woocommerce_order_idor
from .rest_namespace_leak import check as rest_namespace_leak
from .gtm_inventory import check as gtm_inventory
from .uploads_year_listing import check as uploads_year_listing
# Audit-extras-v3 (FEAT-031/047/049)
from .wp_cron_cpu import check as wp_cron_cpu
from .rum_beacons import check as rum_beacons
from .email_obfuscation_audit import check as email_obfuscation_audit
# Audit-extras-v4 (FEAT-016/018/026/030/046)
from .phpinfo_dangerous_directives import check as phpinfo_dangerous_directives
from .db_admin_login_probe import check as db_admin_login_probe
from .debug_log_pii_sniff import check as debug_log_pii_sniff
from .wp_debug_display_via_rest import check as wp_debug_display_via_rest
from .object_cache_dropin import check as object_cache_dropin
# Audit-extras-v5 (FEAT-009/014/017/029/044)
from .xmlrpc_amplification import check as xmlrpc_amplification
from .open_registration import check as open_registration
from .hsts_preload_eligibility import check as hsts_preload_eligibility
from .ct_log_recent_certs import check as ct_log_recent_certs
from .login_redirect_http_hop import check as login_redirect_http_hop
# Audit-extras-v6 (FEAT-011/020/027/007)
from .webhook_signing_secrets import check as webhook_signing_secrets
from .ai_chatbot_endpoint_leak import check as ai_chatbot_endpoint_leak
from .oauth_redirect_misconfig import check as oauth_redirect_misconfig
from .core_checksums import check as core_checksums

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
from .csv_export_csp import check as csv_export_csp
from .waf_bypass_probe import check as waf_bypass_probe
from .xxe_upload import check as xxe_upload

# Round-64 Group F — Modern WP attack-surface (#51-70)
from .ai_prompt_injection_passive import check as ai_prompt_injection_passive
from .wpconfig_hardening_audit import check as wpconfig_hardening_audit
from .db_trigger_audit import check as db_trigger_audit
from .postmeta_stored_xss_scan import check as postmeta_stored_xss_scan
from .vendor_backdoor_patterns import check as vendor_backdoor_patterns
from .cryptominer_js_injection import check as cryptominer_js_injection
from .magecart_skimmer_patterns import check as magecart_skimmer_patterns
from .plugin_typosquat_detection import check as plugin_typosquat_detection
from .composer_lock_audit import check as composer_lock_audit
from .package_lock_audit import check as package_lock_audit
from .yarn_pnpm_lock_audit import check as yarn_pnpm_lock_audit
from .rest_app_passwords_enum import check as rest_app_passwords_enum
from .mfa_priv_account_audit import check as mfa_priv_account_audit
from .wpcron_suspicious_jobs import check as wpcron_suspicious_jobs
from .webhook_url_fingerprint import check as webhook_url_fingerprint
from .git_dir_deep_scan import check as git_dir_deep_scan
from .env_file_enum import check as env_file_enum
from .helm_compose_leak import check as helm_compose_leak
from .tailwind_css_comment_leak import check as tailwind_css_comment_leak
from .graphql_field_authz_deep import check as graphql_field_authz_deep

# Round-64 Group G — Web3/NFT/payment (#71-76)
from .web3_wallet_connector_audit import check as web3_wallet_connector_audit
from .nft_mint_pubapi import check as nft_mint_pubapi
from .crypto_payment_callback_audit import check as crypto_payment_callback_audit
from .solidity_abi_leak import check as solidity_abi_leak
from .wallet_seed_phrase_leak import check as wallet_seed_phrase_leak
from .payment_gateway_test_keys import check as payment_gateway_test_keys

# Round-64 Group J — Accessibility AAA (#99)
from .a11y_wcag_aaa import check as a11y_wcag_aaa

# Round-64 Wild card — Brand monitor (#170)
from .brand_monitor import check as brand_monitor

# ---- v2.6.0 — modern threats (A1-A35 + O141-O145) ----
from .ai_plugin_prompt_storage import check as ai_plugin_prompt_storage
from .ai_agent_webhook_leak import check as ai_agent_webhook_leak
from .mcp_endpoint_exposure import check as mcp_endpoint_exposure
from .wp_playground_sqlite import check as wp_playground_sqlite
from .block_bindings_exposure import check as block_bindings_exposure
from .interactivity_api_state_leak import check as interactivity_api_state_leak
from .wp_cli_http_exposure import check as wp_cli_http_exposure
from .app_passwords_stale_audit import check as app_passwords_stale_audit
from .woo_blocks_checkout_drift import check as woo_blocks_checkout_drift
from .woo_subscriptions_renewal_race import check as woo_subscriptions_renewal_race
from .stripe_webhook_audit import check as stripe_webhook_audit
from .lead_gen_list_id_enum import check as lead_gen_list_id_enum
from .multisite_sso_key_reuse import check as multisite_sso_key_reuse
from .algolia_elastic_frontend_keys import check as algolia_elastic_frontend_keys
from .bucket_shadow_takeover import check as bucket_shadow_takeover
from .vercel_preview_url_leak import check as vercel_preview_url_leak
from .jwt_auth_plugin_audit import check as jwt_auth_plugin_audit
from .pwa_service_worker_cache import check as pwa_service_worker_cache
from .amp_transitional_redirect import check as amp_transitional_redirect
from .cookie_consent_desync import check as cookie_consent_desync
from .gdpr_dsr_endpoint_enum import check as gdpr_dsr_endpoint_enum
from .plugin_install_rest_race import check as plugin_install_rest_race
from .form_builder_upload_bypass import check as form_builder_upload_bypass
from .theme_json_font_ssrf import check as theme_json_font_ssrf
from .search_highlight_xss import check as search_highlight_xss
from .wp_mail_smtp_site_health_leak import check as wp_mail_smtp_site_health_leak
from .translation_plugin_key_leak import check as translation_plugin_key_leak
from .wc_api_key_escalation import check as wc_api_key_escalation
from .service_worker_scope_hijack import check as service_worker_scope_hijack
from .hsts_preload_mismatch import check as hsts_preload_mismatch
from .ct_log_shadow_cert import check as ct_log_shadow_cert
from .turnstile_sitekey_reuse import check as turnstile_sitekey_reuse
from .admin_invite_link_scan import check as admin_invite_link_scan
from .composer_npm_typosquat import check as composer_npm_typosquat
from .github_actions_workflow_leak import check as github_actions_workflow_leak
from .speculation_rules_audit import check as speculation_rules_audit
from .html_api_csp_nonce import check as html_api_csp_nonce
from .font_library_api_ssrf import check as font_library_api_ssrf
from .rest_schema_field_leak import check as rest_schema_field_leak
from .block_style_variations_url import check as block_style_variations_url
from .companion_v13 import check as companion_v13
from .host_platform_detect import check as host_platform_detect
from .companion_v14 import check as companion_v14
from .trellis_yaml_audit import check as trellis_yaml_audit
from .headless_vercel_netlify_detect import check as headless_vercel_netlify_detect
from .perf_of_target import check as perf_of_target
# F1 + F12 (v2.8.0) — new check modules
from .wc_coupon_enum import check as wc_coupon_enum
from .headless_cors_lockdown import check as headless_cors_lockdown

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
    ("a11y_lite",          "Accessibility smoke check",   a11y_lite,         False),
    ("smuggling_probe",    "HTTP request-smuggling indicators", smuggling_probe, False),
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
    ("referenced_buckets", "Referenced-bucket open-listing probe (S3/GCS/R2/Spaces)", referenced_buckets, False),
    ("cloudflare_origin_leak", "Cloudflare origin-IP leak via crt.sh + DNS history", cloudflare_origin_leak, False),
    ("crlf_location_injection", "CRLF injection in Location header (redirect endpoints)", crlf_location_injection, False),
    ("host_header_validation", "Host-header validation on admin endpoints (DNS-rebinding)", host_header_validation, False),
    ("woocommerce_storefront", "WC coupon-enum throttle + fragments cache-poisoning", woocommerce_storefront, False),
    ("page_builder_cve", "Page-builder fingerprint + known-CVE family hint", page_builder_cve, False),
    ("wp_fork_detection", "WP fork detection (ClassicPress / Bedrock / headless)", wp_fork_detection, False),
    ("tls_modern", "TLS modern features: 0-RTT replay-risk + OCSP stapling + must-staple", tls_modern, False),
    ("companion_advanced", "Companion v1.1 endpoints: failed-login geo, Tor admin, backups, perms, 2FA", companion_advanced, False),
    ("waf_lockout_guard", "Early-abort guard: avoid IP-ban escalation when WAF blocks the first probe", waf_lockout_guard, False),
    ("github_leak_search", "GitHub leaked-token search (opt-in)", github_leak_search, False),
    ("jwt_audit",          "JWT audit (alg=none + weak HS256)", jwt_audit,        False),
    # ---- CVE matching ----
    ("hibp",               "HaveIBeenPwned lookup",      hibp,               False),
    ("core_cves",          "Core CVE matching",          core_cves,          False),
    ("plugin_cves",        "Plugin CVE matching",        plugin_cves,        False),
    ("plugin_cemetery",    "Abandoned-plugin detector (wp.org last_updated)", plugin_cemetery, False),
    ("theme_cves",         "Theme CVE matching",         theme_cves,         False),
    # ---- Audit-extras-v1 (FEAT-001/021/032/035/037/040) ----
    ("php_eol",                    "PHP end-of-life audit",                       php_eol,                    False),
    ("permissions_policy",         "Permissions-Policy header audit",             permissions_policy,         False),
    ("heartbeat_frontend",         "Heartbeat API on front-end",                  heartbeat_frontend,         False),
    ("users_me_capability_leak",   "REST /users/me unauthenticated capabilities", users_me_capability_leak,   False),
    ("rest_link_header",           "Link: header leaks internal URLs",            rest_link_header,           False),
    ("csp_report_endpoint",        "CSP report-uri/report-to endpoint health",    csp_report_endpoint,        False),
    # ---- Audit-extras-v2 (FEAT-004/008/013/023/033/041) ----
    ("wp_cron_disabled",           "DISABLE_WP_CRON without replacement",         wp_cron_disabled,           False),
    ("rest_fields_dos",            "REST _fields=* DoS amplification probe",      rest_fields_dos,            False),
    ("woocommerce_order_idor",     "Unauthenticated WC order IDOR probe",         woocommerce_order_idor,     False),
    ("rest_namespace_leak",        "REST namespace internal-name leak",           rest_namespace_leak,        False),
    ("gtm_inventory",              "Google Tag Manager container inventory",       gtm_inventory,              False),
    ("uploads_year_listing",       "/wp-content/uploads/YYYY/ directory listing",  uploads_year_listing,       False),
    # ---- Audit-extras-v3 (FEAT-031/047/049) ----
    ("wp_cron_cpu",                "wp-cron.php response-time amplification",     wp_cron_cpu,                False),
    ("rum_beacons",                "RUM beacon library detection",                rum_beacons,                False),
    ("email_obfuscation_audit",    "Email obfuscation + raw-address leak audit",  email_obfuscation_audit,    False),
    # ---- Audit-extras-v4 (FEAT-016/018/026/030/046) ----
    ("phpinfo_dangerous_directives","phpinfo() dangerous-runtime-flag audit",     phpinfo_dangerous_directives, False),
    ("db_admin_login_probe",        "Adminer/phpMyAdmin login-form depth probe",  db_admin_login_probe,         False),
    ("debug_log_pii_sniff",         "debug.log PII content sniff",                debug_log_pii_sniff,          False),
    ("wp_debug_display_via_rest",   "WP_DEBUG_DISPLAY via malformed REST POST",   wp_debug_display_via_rest,    False),
    ("object_cache_dropin",         "/wp-content/object-cache.php drop-in audit", object_cache_dropin,          False),
    # ---- Audit-extras-v5 (FEAT-009/014/017/029/044) ----
    ("xmlrpc_amplification",        "xmlrpc.php multicall amplification ratio",   xmlrpc_amplification,         False),
    ("open_registration",           "Open registration without membership plugin", open_registration,           False),
    ("hsts_preload_eligibility",    "HSTS preload eligibility audit",             hsts_preload_eligibility,     False),
    ("ct_log_recent_certs",         "CT-log recent unexpected cert issuances",    ct_log_recent_certs,          False),
    ("login_redirect_http_hop",     "HTTP hop in /wp-login.php redirect chain",   login_redirect_http_hop,      False),
    # ---- Audit-extras-v6 (FEAT-011/020/027/007) ----
    ("webhook_signing_secrets",     "Payment-webhook signing-secret leak",         webhook_signing_secrets,      False),
    ("ai_chatbot_endpoint_leak",    "AI-chatbot REST endpoint PII leak",           ai_chatbot_endpoint_leak,     False),
    ("oauth_redirect_misconfig",    "OAuth redirect_uri staging/localhost misconfig", oauth_redirect_misconfig,  False),
    ("core_checksums",              "WP core file checksums vs wp.org manifest",   core_checksums,               False),
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
    # ---- Round-58 passive checks ----
    ("gutenberg_blocks",         "Gutenberg block CVE scanner (#1)", gutenberg_blocks, False),
    ("wp_cron_dos",              "wp-cron.php DoS amplification (#2)", wp_cron_dos, False),
    ("rest_permission_audit",    "REST permission_callback audit (#3)", rest_permission_audit, False),
    ("wp_salts_age",             "WP salts age check (#5+#6)", wp_salts_age, False),
    ("heartbeat_abuse",          "Heartbeat API DoS surface (#7)", heartbeat_abuse, False),
    ("woocommerce_deep",         "WC consumer-key/IDOR deep audit (#8+#9)", woocommerce_deep, False),
    ("plugin_specific_audit",    "ACF/MS/agent/child/WP-CLI audit (#11-15)", plugin_specific_audit, False),
    ("hosting_platform_audit",   "WP Engine/Kinsta/CF/Amplify audits (#16-22)", hosting_platform_audit, False),
    ("origin_ip_discovery",      "Origin-IP discovery via subdomains (#23)", origin_ip_discovery, False),
    ("tls_reneg_dos",            "TLS renegotiation DoS probe (#26)", tls_reneg_dos, False),
    ("osint_enrich",             "OSINT — ASN/geo/bug-bounty/cert TX (#36-43)", osint_enrich, False),
    # ---- Round-59 passive checks (111 features) ----
    ("wp_builder_audit",         "Block-theme/FSE + page-builder audit (#1-2)", wp_builder_audit, False),
    ("wp_form_audit",            "Form-plugin deep audit (CF7/WPF/GF/NF/FF/Formidable) (#3)", wp_form_audit, False),
    ("wp_membership_lms_audit",  "Membership + LMS plugin audit (#4-5)", wp_membership_lms_audit, False),
    ("wp_commerce_alt_audit",    "Alt-commerce + booking-plugin audit (#6+8)", wp_commerce_alt_audit, False),
    ("wp_plugin_ecosystem_audit","Search/SEO/Backup/SMTP/Cache/CDN/Sec/Chat plugin audit (#7,#9-15)", wp_plugin_ecosystem_audit, False),
    ("privacy_inventory",        "Privacy/GDPR data + tracker inventory (#16-23)", privacy_inventory, False),
    ("email_security_deep",      "Email deep — DMARC/MTA-STS/BIMI/ARC/DKIM/SPF (#24-31)", email_security_deep, False),
    ("dns_deep",                 "DNS deep — DNSSEC/CAA/TXT-secret/DoH/PTR/wildcard (#32-39)", dns_deep, False),
    ("auth_modernisation",       "Auth modernisation — passkey/2FA/SAML/OAuth/JWT/magic-link (#40-46)", auth_modernisation, False),
    ("crypto_agility",           "Crypto agility — PQ/TLS 1.3 hybrid/cert inventory (#47-51)", crypto_agility, False),
    ("cdn_edge_audit",           "CDN edge audit — Workers/CF/Fastly/Bunny/KeyCDN (#52-57)", cdn_edge_audit, False),
    ("payment_commerce_deep",    "Payment/PCI 4.0 deep audit (#58-62)", payment_commerce_deep, False),
    ("compliance_frameworks",    "Compliance framework mapping — HITRUST/CMMC/NIST CSF/CIS/ISO (#63-67)", compliance_frameworks, False),
    ("headless_wp_audit",        "Headless/API-first WP audit (#87-91)", headless_wp_audit, False),
    # ---- Round-60 passive checks ----
    ("wp_multisite_deep",        "WP-Multisite per-blog deep audit (#17)", wp_multisite_deep, False),
    ("honeypot_admin",           "Honeypot / anti-spam detection (#19)", honeypot_admin, False),
    ("a11y_deep",                "WCAG 2.2 accessibility deep audit (#24)", a11y_deep, False),
    ("perf_budget",              "Performance-budget audit (#25)", perf_budget, False),
    # ---- Round-62 passive checks (B21-B38) ----
    ("server_stack_reveal",      "Server-stack reveal + PHP EOL detect (#B22+B29)", server_stack_reveal, False),
    ("waf_brand_deep",           "WAF brand deep-detect — 11 vendors (#B23)", waf_brand_deep, False),
    ("sri_audit",                "Subresource Integrity (SRI) audit (#B24)", sri_audit, False),
    ("service_exposure",         "Service-port exposure: Redis/Memcache/DB (#B35-B37)", service_exposure, False),
    ("js_framework_deep",        "JS framework deep-detect + version pin (#B31)", js_framework_deep, False),
    ("sri_pwa_misc",             "SameSite/WebDAV/PWA/HTTP3/contrast (#B25+B30+B32-B34)", sri_pwa_misc, False),
    ("wp_cli_inject",            "WP-CLI command-injection probe (#B28)", wp_cli_inject, True),
    # ---- Round-64 Group F — Modern WP attack-surface (#51-70) ----
    ("ai_prompt_injection_passive", "AI/LLM-plugin prompt-injection surface (#51)", ai_prompt_injection_passive, False),
    ("wpconfig_hardening_audit", "wp-config hardening inferred from remote signals (#52)", wpconfig_hardening_audit, False),
    ("db_trigger_audit",         "MySQL trigger audit via companion plugin (#53)", db_trigger_audit, False),
    ("postmeta_stored_xss_scan", "post_meta stored-XSS scan via REST (#54)", postmeta_stored_xss_scan, False),
    ("vendor_backdoor_patterns", "Known-bad / vendor-backdoor plugin slugs (#55)", vendor_backdoor_patterns, False),
    ("cryptominer_js_injection", "Cryptominer JS injection (#56)", cryptominer_js_injection, False),
    ("magecart_skimmer_patterns","Magecart / card-skimmer DOM hooks (#57)", magecart_skimmer_patterns, False),
    ("plugin_typosquat_detection","Plugin slug typosquat detection (#58)", plugin_typosquat_detection, False),
    ("composer_lock_audit",      "composer.lock exposure + CVE check (#59)", composer_lock_audit, False),
    ("package_lock_audit",       "package-lock.json exposure + CVE check (#60)", package_lock_audit, False),
    ("yarn_pnpm_lock_audit",     "yarn.lock / pnpm-lock.yaml exposure (#61)", yarn_pnpm_lock_audit, False),
    ("rest_app_passwords_enum",  "REST Application Passwords auth probe (#62)", rest_app_passwords_enum, False),
    ("mfa_priv_account_audit",   "MFA on privileged accounts (companion) (#63)", mfa_priv_account_audit, False),
    ("wpcron_suspicious_jobs",   "Suspicious wp-cron callbacks (companion) (#64)", wpcron_suspicious_jobs, False),
    ("webhook_url_fingerprint",  "Webhook URL fingerprint (Discord/Slack/Telegram) (#65)", webhook_url_fingerprint, False),
    ("git_dir_deep_scan",        "Deep .git directory enumeration (#66)", git_dir_deep_scan, False),
    ("env_file_enum",            ".env file exposure + secret sniffing (#67)", env_file_enum, False),
    ("helm_compose_leak",        "Helm/compose/k8s manifest exposure (#68)", helm_compose_leak, False),
    ("tailwind_css_comment_leak","Tailwind/CSS filesystem-path leak (#69)", tailwind_css_comment_leak, False),
    ("graphql_field_authz_deep", "GraphQL field-level authz deep probe (#70)", graphql_field_authz_deep, False),
    # ---- Round-64 Group G — Web3/NFT/payment (#71-76) ----
    ("web3_wallet_connector_audit", "Web3 wallet-connector plugin audit (#71)", web3_wallet_connector_audit, False),
    ("nft_mint_pubapi",          "NFT mint endpoint public-access probe (#72)", nft_mint_pubapi, False),
    ("crypto_payment_callback_audit","Crypto-payment webhook auth audit (#73)", crypto_payment_callback_audit, False),
    ("solidity_abi_leak",        "Solidity contract ABI leak (#74)", solidity_abi_leak, False),
    ("wallet_seed_phrase_leak",  "Wallet seed phrase leak (BIP-39 scan) (#75)", wallet_seed_phrase_leak, False),
    ("payment_gateway_test_keys","Payment-gateway test/sandbox key leak (#76)", payment_gateway_test_keys, False),
    # ---- Round-64 Group J — Accessibility (#99) + Wild card (#170) ----
    ("a11y_wcag_aaa",            "WCAG 2.2 AAA-level accessibility extras (#99)", a11y_wcag_aaa, False),
    ("brand_monitor",            "Typosquat-of-your-domain brand monitor (#170)", brand_monitor, False),
    # ---- v2.6.0 — modern threats (A1-A35 + O141-O145) ----
    ("ai_plugin_prompt_storage", "AI plugin prompt-injection surface (A1)", ai_plugin_prompt_storage, False),
    ("ai_agent_webhook_leak",    "AI chatbot relay-endpoint / key leak (A2)", ai_agent_webhook_leak, False),
    ("mcp_endpoint_exposure",    "MCP (Model Context Protocol) endpoint exposure (A3)", mcp_endpoint_exposure, False),
    ("wp_playground_sqlite",     "WP Playground / SQLite database file exposure (A4)", wp_playground_sqlite, False),
    ("block_bindings_exposure",  "Gutenberg Block-Bindings custom-source audit (A5)", block_bindings_exposure, False),
    ("interactivity_api_state_leak", "Interactivity-API hydration state PII leak (A6)", interactivity_api_state_leak, False),
    ("wp_cli_http_exposure",     "WP-CLI-over-HTTP endpoint exposure (A7)", wp_cli_http_exposure, False),
    ("app_passwords_stale_audit","Application Passwords stale-token audit (A8, auth)", app_passwords_stale_audit, False),
    ("woo_blocks_checkout_drift", "WooCommerce Store API namespace drift (A9)", woo_blocks_checkout_drift, False),
    ("woo_subscriptions_renewal_race", "WC Subscriptions duplicate-renewal race patch audit (A10)", woo_subscriptions_renewal_race, False),
    ("stripe_webhook_audit",     "Stripe / WooPayments webhook signature audit (A11)", stripe_webhook_audit, False),
    ("lead_gen_list_id_enum",    "Klaviyo / Mailchimp list-ID enumeration (A12)", lead_gen_list_id_enum, False),
    ("multisite_sso_key_reuse",  "WP Multisite SSO key reuse audit (A13)", multisite_sso_key_reuse, False),
    ("algolia_elastic_frontend_keys", "Algolia / ES write-key leak in frontend JS (A14)", algolia_elastic_frontend_keys, False),
    ("bucket_shadow_takeover",   "S3 / R2 / GCS shadow-bucket takeover (A15)", bucket_shadow_takeover, False),
    ("vercel_preview_url_leak",  "Vercel / Netlify preview-URL leak (A16)", vercel_preview_url_leak, False),
    ("jwt_auth_plugin_audit",    "JWT-Auth plugin secret-key audit (A17)", jwt_auth_plugin_audit, False),
    ("pwa_service_worker_cache", "PWA service-worker precaches admin URLs (A18)", pwa_service_worker_cache, False),
    ("amp_transitional_redirect","AMP plugin transitional-mode open-redirect (A19)", amp_transitional_redirect, False),
    ("cookie_consent_desync",    "Tracking cookies fire pre-consent (A20)", cookie_consent_desync, False),
    ("gdpr_dsr_endpoint_enum",   "GDPR DSR ajax-action auth check (A21)", gdpr_dsr_endpoint_enum, False),
    ("plugin_install_rest_race", "REST plugin-install endpoint auth audit (A22)", plugin_install_rest_race, False),
    ("form_builder_upload_bypass","Form-builder file-upload bypass advisory (A23)", form_builder_upload_bypass, False),
    ("theme_json_font_ssrf",     "theme.json font-source SSRF surface (A24)", theme_json_font_ssrf, False),
    ("search_highlight_xss",     "Search-result <mark> reflected XSS (A25)", search_highlight_xss, False),
    ("wp_mail_smtp_site_health_leak", "Site-Health debug dump SMTP-key leak (A26)", wp_mail_smtp_site_health_leak, False),
    ("translation_plugin_key_leak","Translation plugin API key leak (A27)", translation_plugin_key_leak, False),
    ("wc_api_key_escalation",    "WooCommerce REST key scope advisory (A28)", wc_api_key_escalation, False),
    ("service_worker_scope_hijack","Service-worker origin-wide scope (A29)", service_worker_scope_hijack, False),
    ("hsts_preload_mismatch",    "HSTS preload list vs header mismatch (A30)", hsts_preload_mismatch, False),
    ("ct_log_shadow_cert",       "CT-log shadow certificate detection (A31)", ct_log_shadow_cert, False),
    ("turnstile_sitekey_reuse",  "Captcha sitekey placeholder / domain audit (A32)", turnstile_sitekey_reuse, False),
    ("admin_invite_link_scan",   "Discord/Slack/Telegram invite leak (A33)", admin_invite_link_scan, False),
    ("composer_npm_typosquat",   "Composer/npm typosquat dep advisory (A34)", composer_npm_typosquat, False),
    ("github_actions_workflow_leak","CI workflow YAML exposed on webroot (A35)", github_actions_workflow_leak, False),
    ("speculation_rules_audit",  "WP 6.8 Speculation Rules audit (O141)", speculation_rules_audit, False),
    ("html_api_csp_nonce",       "WP 6.7 HTML API breaks CSP nonces (O142)", html_api_csp_nonce, False),
    ("font_library_api_ssrf",    "WP 6.5 Font Library SSRF audit (O143)", font_library_api_ssrf, False),
    ("rest_schema_field_leak",   "REST schema-callback field leak (O144)", rest_schema_field_leak, False),
    ("block_style_variations_url","Block-style URL-prop SSRF (O145)", block_style_variations_url, False),
    ("companion_v13",            "Companion v1.3 endpoint consumers (B36-B47)", companion_v13, False),
    ("host_platform_detect",     "Host stack / platform fingerprint (N136/N139/N140)", host_platform_detect, False),
    ("companion_v14",            "Companion v1.4 endpoint consumers (B38-B45)", companion_v14, False),
    ("trellis_yaml_audit",       "Roots Trellis YAML exposure (N137)", trellis_yaml_audit, False),
    ("headless_vercel_netlify_detect", "Headless WP on Vercel/Netlify with reachable REST (N138)", headless_vercel_netlify_detect, False),
    ("perf_of_target",           "Operational perf audit: TTFB / Lighthouse / DB-queries / cache-hit / cold-start (P146-P150)", perf_of_target, False),
    # ---- Round-58 aggressive checks ----
    ("wp_query_sqli",            "WP_Query/wpdb-specific SQLi (#4)", wp_query_sqli, True),
    # v2.8.1 B28 — http2_smuggling removed. The detection required the
    # server to echo a CRLF-injected `X-Injected` header back, but
    # httpx client-side validation rejects CRLF in headers before they
    # ever reach the wire — so the check could never fire. Re-add when
    # there's a raw-socket-based redesign.
    ("upload_bypass_deep",       "Upload SVG-XXE/polyglot/TOCTOU (#28-30)", upload_bypass_deep, True),
    ("misc_injection_audit",     "LDAP/XPath/SSI/ESI/CRLF/email-header (#32-34)", misc_injection_audit, True),
    ("cache_poisoning_v2",       "Cache poisoning chain v2 (#35)", cache_poisoning_v2, True),
    # ---- Round-57 aggressive checks ----
    ("plugin_archive_fuzz","Plugin source-archive fuzz (#6)", plugin_archive_fuzz, True),
    ("headless_templates", "Headless DOM templates (Playwright) (#14)", headless_templates, True),
    ("websocket_fuzz",     "WebSocket frame fuzzer (#23)", websocket_fuzz, True),
    # F1 + F12 (v2.8.0) — new passive checks; non-aggressive (no auth,
    # no destructive probes). WC coupon enum sends 5 fake codes only;
    # headless CORS lockdown is a 3-GET probe.
    ("wc_coupon_enum",         "WC coupon-code enumeration oracle (F1)", wc_coupon_enum,         False),
    ("headless_cors_lockdown", "Headless WP REST CORS lockdown (F12)",   headless_cors_lockdown, False),
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
    import json
    import sys
    from pathlib import Path
    import os
    home = os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan")
    f = Path(home) / "disabled_checks.json"
    if not f.exists():
        return set()
    try:
        return set(json.loads(f.read_text(encoding="utf-8")) or [])
    except json.JSONDecodeError as e:
        # L3: warn loudly — silently re-enabling all previously-disabled
        # checks on a corrupt JSON file would surprise the operator with
        # a flood of findings they thought were suppressed.
        print(f"warning: {f} is malformed JSON ({e}); ALL previously-disabled "
               f"checks are now re-enabled. Fix or remove the file.",
               file=sys.stderr)
        return set()
    except OSError:
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
        # Q9: single source of truth for custom-check search paths.
        from .._util import custom_check_dirs
        search_dirs = custom_check_dirs()
        existing_ids = {cid for cid, _n, _f, _a in ALL_CHECKS}
        py_files: list[Path] = []
        for d in search_dirs:
            if d.exists():
                py_files.extend(sorted(d.glob("*.py")))
        for py_file in py_files:
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
