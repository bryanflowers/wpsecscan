# WPSecScan check catalogue

Auto-generated from check docstrings. 161 checks total.

| Check ID | Display name | Aggressive | OWASP | MITRE |
|----------|--------------|-----------|-------|-------|
| [`waf`](waf.md) | WAF / CDN detection | · | A05:2021 | T1592.004 |
| [`core_version`](core_version.md) | WordPress core version | · | A06:2021 | T1592.002 |
| [`plugins`](plugins.md) | Plugin enumeration | · | A06:2021 | T1592.002 |
| [`themes`](themes.md) | Theme enumeration | · | A06:2021 | T1592.002 |
| [`users`](users.md) | User enumeration | · | A07:2021 | T1589.002 |
| [`exposed_files`](exposed_files.md) | Exposed files | · | A05:2021 | T1083 |
| [`login`](login.md) | Login surface | · | A07:2021 | T1110.001 |
| [`login_throttle`](login_throttle.md) | Login rate-limiting test | · | A07:2021 | T1110.003 |
| [`tls_headers`](tls_headers.md) | TLS & security headers | · | A05:2021 | T1071.001 |
| [`csp`](csp.md) | CSP deep analysis | · | A05:2021 | T1059.007 |
| [`cookies`](cookies.md) | Cookie hardening | · | A07:2021 | T1539 |
| [`http_methods`](http_methods.md) | HTTP method enumeration | · | A05:2021 | T1190 |
| [`directory_listing`](directory_listing.md) | Directory listing | · | A05:2021 | T1083 |
| [`debug_leaks`](debug_leaks.md) | Debug & info leaks | · | A09:2021 | T1592.004 |
| [`robots_sitemap`](robots_sitemap.md) | robots.txt / sitemap audit | · | A05:2021 | T1593.003 |
| [`subdomains`](subdomains.md) | Subdomain discovery | · | A05:2021 | T1590.005 |
| [`rest_api`](rest_api.md) | WP REST API surface audit | · | A01:2021 | T1190 |
| [`cors`](cors.md) | CORS misconfiguration | · | A05:2021 | T1190 |
| [`js_libraries`](js_libraries.md) | JS library version audit | · | A06:2021 | T1059.007 |
| [`secret_leak`](secret_leak.md) | Accidental API-key leak scan | · | A02:2021 | T1552.001 |
| [`wpgraphql`](wpgraphql.md) | WPGraphQL endpoint audit | · | A01:2021 | T1190 |
| [`backup_exposure`](backup_exposure.md) | Backup-plugin file exposure | · | A05:2021 | T1530 |
| [`csrf_nonce`](csrf_nonce.md) | CSRF / nonce form audit | · | A01:2021 | T1190 |
| [`app_passwords`](app_passwords.md) | Application Passwords audit | · | A07:2021 | T1078 |
| [`mixed_content`](mixed_content.md) | Mixed-content (HTTP-in-HTTPS) audit | · | A02:2021 | T1557 |
| [`tls_deep`](tls_deep.md) | Deep TLS audit | · | A02:2021 | T1557 |
| [`multisite`](multisite.md) | WordPress Multisite audit | · | A01:2021 | T1078 |
| [`webhooks`](webhooks.md) | Webhook endpoint discovery | · | A10:2021 | T1190 |
| [`cache_headers`](cache_headers.md) | Cache-header audit | · | A04:2021 | T1556 |
| [`xmlrpc_deep`](xmlrpc_deep.md) | XML-RPC method enumeration | · | A07:2021 | T1110.004 |
| [`redirect_chain`](redirect_chain.md) | Redirect chain analysis | · | A10:2021 | T1071.001 |
| [`error_pages`](error_pages.md) | Error-page fingerprinting | · | A05:2021 | T1592.002 |
| [`xss_dom_sinks`](xss_dom_sinks.md) | DOM-XSS source/sink scan | · | A03:2021 | T1059.007 |
| [`nonce_freshness`](nonce_freshness.md) | WP nonce freshness audit | · | A01:2021 | T1078 |
| [`security_txt`](security_txt.md) | security.txt (RFC 9116) audit | · | A09:2021 | T1592.004 |
| [`favicon_fingerprint`](favicon_fingerprint.md) | Favicon fingerprint | · | A05:2021 | T1592.002 |
| [`admin_ajax_brute_surface`](admin_ajax_brute_surface.md) | admin-ajax throttle probe | · | A07:2021 | T1110.001 |
| [`dns_security`](dns_security.md) | DNS security (SPF/DMARC/DKIM) | · | A05:2021 | T1566.001 |
| [`source_maps`](source_maps.md) | Source-map exposure | · | A02:2021 | T1552.001 |
| [`js_supply_chain`](js_supply_chain.md) | External JS supply-chain audit | · | A08:2021 | T1195.002 |
| [`server_timing`](server_timing.md) | Server-Timing / debug headers | · | A09:2021 | T1592.002 |
| [`wp_rest_methods`](wp_rest_methods.md) | REST method enumeration | · | A01:2021 | T1190 |
| [`gdpr_dsr`](gdpr_dsr.md) | GDPR Data-Subject-Request audit | · | A04:2021 | T1592.001 |
| [`wp_engine_misconfig`](wp_engine_misconfig.md) | WP Engine private-path leaks | · | A05:2021 | T1190 |
| [`oauth_redirect`](oauth_redirect.md) | OAuth / login redirect-URI | · | A01:2021 | T1204.001 |
| [`cache_poisoning`](cache_poisoning.md) | Web-cache poisoning probe | · | A05:2021 | T1190 |
| [`upload_path_predictable`](upload_path_predictable.md) | Predictable upload paths | · | A01:2021 | T1083 |
| [`http2_settings`](http2_settings.md) | HTTP/2 fingerprint + EOL backend | · | A06:2021 | T1592.002 |
| [`favicon_hash`](favicon_hash.md) | Favicon fingerprint hash (Shodan) | · | A05:2021 | T1592.004 |
| [`a11y_lite`](a11y_lite.md) | Accessibility smoke check | · | A04:2021 | T1592.004 |
| [`smuggling_probe`](smuggling_probe.md) | HTTP request-smuggling indicators | · | A03:2021 | T1190 |
| [`tls_protocol_audit`](tls_protocol_audit.md) | Deep TLS protocol + cipher + cert audit | · | A02:2021 | T1557 |
| [`cookie_consent`](cookie_consent.md) | GDPR/ePrivacy cookie-consent audit | · | A04:2021 | T1592.004 |
| [`websocket_audit`](websocket_audit.md) | WebSocket upgrade + origin audit | · | A01:2021 | T1190 |
| [`woocommerce_audit`](woocommerce_audit.md) | WooCommerce REST + legacy-API audit | · | A01:2021 | T1190 |
| [`graphql_dos`](graphql_dos.md) | GraphQL alias-amplification DoS | · | A04:2021 | T1499.002 |
| [`well_known`](well_known.md) | /.well-known/ resource enumeration | · | A05:2021 | T1592.004 |
| [`login_timing`](login_timing.md) | Login timing side-channel (user enum) | · | A07:2021 | T1589.002 |
| [`sitemap_cve_probe`](sitemap_cve_probe.md) | Sitemap-driven CVE pattern probe | · | A06:2021 | T1190 |
| [`webdav`](webdav.md) | WebDAV / OPTIONS enumeration | · | A05:2021 | T1190 |
| [`dev_params`](dev_params.md) | Beta/test/debug query parameters | · | A05:2021 | T1592.004 |
| [`abuseipdb_lookup`](abuseipdb_lookup.md) | AbuseIPDB reputation (opt-in) | · | A05:2021 | T1590.005 |
| [`waf_ruleset`](waf_ruleset.md) | WAF rule-set identification | · | A05:2021 | T1592.004 |
| [`oauth_oidc`](oauth_oidc.md) | OAuth2 / OIDC discovery audit | · | A07:2021 | T1078.004 |
| [`saml_xsw`](saml_xsw.md) | SAML / XSW endpoint discovery | · | A07:2021 | T1078.004 |
| [`s3_bucket_discovery`](s3_bucket_discovery.md) | S3 bucket discovery + public-ACL | · | A05:2021 | T1530 |
| [`github_leak_search`](github_leak_search.md) | GitHub leaked-token search (opt-in) | · | A02:2021 | T1552.001 |
| [`jwt_audit`](jwt_audit.md) | JWT audit (alg=none + weak HS256) | · | A02:2021 | T1552.001 |
| [`hibp`](hibp.md) | HaveIBeenPwned lookup | · | A07:2021 | T1589.001 |
| [`core_cves`](core_cves.md) | Core CVE matching | · | A06:2021 | T1190 |
| [`plugin_cves`](plugin_cves.md) | Plugin CVE matching | · | A06:2021 | T1190 |
| [`theme_cves`](theme_cves.md) | Theme CVE matching | · | A06:2021 | T1190 |
| [`sqli`](sqli.md) | SQL injection probes | ⚠ | A03:2021 | T1190 |
| [`xss_reflected`](xss_reflected.md) | Reflected XSS probes | ⚠ | A03:2021 | T1059.007 |
| [`open_redirect`](open_redirect.md) | Open-redirect probes | ⚠ | A10:2021 | T1204.001 |
| [`ssrf`](ssrf.md) | SSRF probes | ⚠ | A10:2021 | T1090 |
| [`path_traversal`](path_traversal.md) | Path traversal probes | ⚠ | A01:2021 | T1083 |
| [`file_upload`](file_upload.md) | Upload-endpoint probes | ⚠ | A04:2021 | T1505.003 |
| [`default_creds`](default_creds.md) | Default credentials probe | ⚠ | A07:2021 | T1078.001 |
| [`ajax_surface`](ajax_surface.md) | admin-ajax action surface | ⚠ | A01:2021 | T1190 |
| [`core_tampering`](core_tampering.md) | Core file tampering check | ⚠ | A08:2021 | T1505.003 |
| [`sendmail_injection`](sendmail_injection.md) | Email header injection probe | ⚠ | A03:2021 | T1190 |
| [`prototype_pollution`](prototype_pollution.md) | Prototype-pollution reflection probe | ⚠ | A03:2021 | T1059.007 |
| [`graphql_field_dos`](graphql_field_dos.md) | GraphQL query-depth DoS probe | ⚠ | A04:2021 | T1499.002 |
| [`csv_export_csp`](csv_export_csp.md) | CSV-export formula-injection probe | ⚠ | A03:2021 | T1204.002 |
| [`waf_bypass_probe`](waf_bypass_probe.md) | WAF bypass/passthrough probe | ⚠ | A05:2021 | T1190 |
| [`xxe_upload`](xxe_upload.md) | XXE via SVG upload probe | ⚠ | A05:2021 | T1190 |
| [`ssti`](ssti.md) | Server-side template injection probe | ⚠ | A03:2021 | T1190 |
| [`nosql_injection`](nosql_injection.md) | NoSQL operator injection probe | ⚠ | A03:2021 | T1190 |
| [`path_bypass`](path_bypass.md) | Path-normalisation bypass probe | ⚠ | A01:2021 | T1083 |
| [`race_condition`](race_condition.md) | Race-condition probe (parallel POSTs) | ⚠ | A04:2021 | T1499 |
| [`dom_xss_headless`](dom_xss_headless.md) | Headless DOM-XSS (Playwright, opt-in) | ⚠ | A03:2021 | T1059.007 |
| [`http3_fingerprint`](http3_fingerprint.md) | HTTP/3 + QUIC fingerprint | · | A05:2021 | T1592.004 |
| [`session_fixation`](session_fixation.md) | Session-fixation precondition probe | · | A07:2021 | T1539 |
| [`csrf_entropy`](csrf_entropy.md) | CSRF nonce entropy sampler | · | A01:2021 | T1190 |
| [`backup_file_fuzz`](backup_file_fuzz.md) | Backup-file long-tail fuzzer | · | A05:2021 | T1083 |
| [`hostname_collision`](hostname_collision.md) | Apex vs www hostname collision | · | A05:2021 | T1583.001 |
| [`plugin_route_fuzz`](plugin_route_fuzz.md) | Plugin REST-route fuzzer | · | A01:2021 | T1190 |
| [`hpp`](hpp.md) | HTTP Parameter Pollution probe | ⚠ | A03:2021 | T1190 |
| [`header_smuggling_case`](header_smuggling_case.md) | Header smuggling via case sensitivity | ⚠ | A05:2021 | T1190 |
| [`cloud_metadata_ssrf`](cloud_metadata_ssrf.md) | Cloud-metadata SSRF chain (needs SSRF candidate) | ⚠ | A10:2021 | T1552.005 |
| [`dns_rebinding`](dns_rebinding.md) | DNS-rebinding SSRF probe | ⚠ | A10:2021 | T1071.004 |
| [`timthumb`](timthumb.md) | timthumb.php CVE detection (#1) | · | A06:2021 | T1190 |
| [`plugin_hash_fingerprint`](plugin_hash_fingerprint.md) | Plugin file-hash fingerprint (#2) | · | A05:2021 | T1592.002 |
| [`users_deep`](users_deep.md) | Deep user enumeration — 10 sources (#5) | · | A07:2021 | T1589.002 |
| [`premium_license_leak`](premium_license_leak.md) | Premium plugin license-key leak scan (#7) | · | A02:2021 | T1552.001 |
| [`xmlrpc_method_brute`](xmlrpc_method_brute.md) | XML-RPC hidden-method brute-force (#8) | · | A05:2021 | T1190 |
| [`yaml_templates`](yaml_templates.md) | YAML templates (nuclei-style) (#9) | · | A05:2021 | T1190 |
| [`yaml_workflows`](yaml_workflows.md) | YAML workflow chaining (#11) | · | A05:2021 | T1190 |
| [`dns_templates`](dns_templates.md) | DNS templates (#13) | · | A05:2021 | T1071.004 |
| [`spider_crawl`](spider_crawl.md) | Spider — recursive link crawler (#18) | · | A05:2021 | T1593 |
| [`forced_browse`](forced_browse.md) | Forced-browse hidden-path discovery (#21) | · | A05:2021 | T1083 |
| [`openapi_scanner`](openapi_scanner.md) | OpenAPI / Swagger endpoint scanner (#26) | · | A05:2021 | T1190 |
| [`mobile_app_endpoints`](mobile_app_endpoints.md) | Mobile-app association discovery (#38) | · | A05:2021 | T1592 |
| [`host_recon`](host_recon.md) | Host port recon — Docker/Redis/k8s/etc. (#40) | · | A05:2021 | T1046 |
| [`gutenberg_blocks`](gutenberg_blocks.md) | Gutenberg block CVE scanner (#1) | · | A06:2021 | T1592.002 |
| [`wp_cron_dos`](wp_cron_dos.md) | wp-cron.php DoS amplification (#2) | · | A04:2021 | T1499.003 |
| [`rest_permission_audit`](rest_permission_audit.md) | REST permission_callback audit (#3) | · | A01:2021 | T1190 |
| [`wp_salts_age`](wp_salts_age.md) | WP salts age check (#5+#6) | · | A02:2021 | T1552 |
| [`heartbeat_abuse`](heartbeat_abuse.md) | Heartbeat API DoS surface (#7) | · | A04:2021 | T1499 |
| [`woocommerce_deep`](woocommerce_deep.md) | WC consumer-key/IDOR deep audit (#8+#9) | · | A01:2021 | T1190 |
| [`plugin_specific_audit`](plugin_specific_audit.md) | ACF/MS/agent/child/WP-CLI audit (#11-15) | · | A05:2021 | T1190 |
| [`hosting_platform_audit`](hosting_platform_audit.md) | WP Engine/Kinsta/CF/Amplify audits (#16-22) | · | A05:2021 | T1592.004 |
| [`origin_ip_discovery`](origin_ip_discovery.md) | Origin-IP discovery via subdomains (#23) | · | A05:2021 | T1590.005 |
| [`tls_reneg_dos`](tls_reneg_dos.md) | TLS renegotiation DoS probe (#26) | · | A02:2021 | T1499 |
| [`osint_enrich`](osint_enrich.md) | OSINT — ASN/geo/bug-bounty/cert TX (#36-43) | · | A05:2021 | T1592 |
| [`wp_builder_audit`](wp_builder_audit.md) | Block-theme/FSE + page-builder audit (#1-2) | · | A06:2021 | T1592.002 |
| [`wp_form_audit`](wp_form_audit.md) | Form-plugin deep audit (CF7/WPF/GF/NF/FF/Formidable) (#3) | · | A05:2021 | T1190 |
| [`wp_membership_lms_audit`](wp_membership_lms_audit.md) | Membership + LMS plugin audit (#4-5) | · | A01:2021 | T1190 |
| [`wp_commerce_alt_audit`](wp_commerce_alt_audit.md) | Alt-commerce + booking-plugin audit (#6+8) | · | A01:2021 | T1190 |
| [`wp_plugin_ecosystem_audit`](wp_plugin_ecosystem_audit.md) | Search/SEO/Backup/SMTP/Cache/CDN/Sec/Chat plugin audit (#7,#9-15) | · | A05:2021 | T1592.002 |
| [`privacy_inventory`](privacy_inventory.md) | Privacy/GDPR data + tracker inventory (#16-23) | · | A09:2021 | T1593 |
| [`email_security_deep`](email_security_deep.md) | Email deep — DMARC/MTA-STS/BIMI/ARC/DKIM/SPF (#24-31) | · | A05:2021 | T1566 |
| [`dns_deep`](dns_deep.md) | DNS deep — DNSSEC/CAA/TXT-secret/DoH/PTR/wildcard (#32-39) | · | A05:2021 | T1071.004 |
| [`auth_modernisation`](auth_modernisation.md) | Auth modernisation — passkey/2FA/SAML/OAuth/JWT/magic-link (#40-46) | · | A07:2021 | T1110 |
| [`crypto_agility`](crypto_agility.md) | Crypto agility — PQ/TLS 1.3 hybrid/cert inventory (#47-51) | · | A02:2021 | T1190 |
| [`cdn_edge_audit`](cdn_edge_audit.md) | CDN edge audit — Workers/CF/Fastly/Bunny/KeyCDN (#52-57) | · | A05:2021 | T1190 |
| [`payment_commerce_deep`](payment_commerce_deep.md) | Payment/PCI 4.0 deep audit (#58-62) | · | A02:2021 | T1190 |
| [`compliance_frameworks`](compliance_frameworks.md) | Compliance framework mapping — HITRUST/CMMC/NIST CSF/CIS/ISO (#63-67) | · | A05:2021 | T1499 |
| [`headless_wp_audit`](headless_wp_audit.md) | Headless/API-first WP audit (#87-91) | · | A01:2021 | T1190 |
| [`wp_multisite_deep`](wp_multisite_deep.md) | WP-Multisite per-blog deep audit (#17) | · | A01:2021 | T1190 |
| [`honeypot_admin`](honeypot_admin.md) | Honeypot / anti-spam detection (#19) | · | A09:2021 | T1078 |
| [`a11y_deep`](a11y_deep.md) | WCAG 2.2 accessibility deep audit (#24) | · | A05:2021 | T1592 |
| [`perf_budget`](perf_budget.md) | Performance-budget audit (#25) | · | A04:2021 | T1499 |
| [`server_stack_reveal`](server_stack_reveal.md) | Server-stack reveal + PHP EOL detect (#B22+B29) | · | A05:2021 | T1592.002 |
| [`waf_brand_deep`](waf_brand_deep.md) | WAF brand deep-detect — 11 vendors (#B23) | · | A05:2021 | T1592.004 |
| [`sri_audit`](sri_audit.md) | Subresource Integrity (SRI) audit (#B24) | · | A08:2021 | T1195.002 |
| [`service_exposure`](service_exposure.md) | Service-port exposure: Redis/Memcache/DB (#B35-B37) | · | A05:2021 | T1046 |
| [`js_framework_deep`](js_framework_deep.md) | JS framework deep-detect + version pin (#B31) | · | A06:2021 | T1592.002 |
| [`sri_pwa_misc`](sri_pwa_misc.md) | SameSite/WebDAV/PWA/HTTP3/contrast (#B25+B30+B32-B34) | · | A05:2021 | T1190 |
| [`wp_cli_inject`](wp_cli_inject.md) | WP-CLI command-injection probe (#B28) | ⚠ | A03:2021 | T1059 |
| [`wp_query_sqli`](wp_query_sqli.md) | WP_Query/wpdb-specific SQLi (#4) | ⚠ | A03:2021 | T1190 |
| [`http2_smuggling`](http2_smuggling.md) | HTTP/2 CRLF smuggling probe (#24) | ⚠ | A05:2021 | T1190 |
| [`upload_bypass_deep`](upload_bypass_deep.md) | Upload SVG-XXE/polyglot/TOCTOU (#28-30) | ⚠ | A03:2021 | T1190 |
| [`misc_injection_audit`](misc_injection_audit.md) | LDAP/XPath/SSI/ESI/CRLF/email-header (#32-34) | ⚠ | A03:2021 | T1190 |
| [`cache_poisoning_v2`](cache_poisoning_v2.md) | Cache poisoning chain v2 (#35) | ⚠ | A05:2021 | T1190 |
| [`plugin_archive_fuzz`](plugin_archive_fuzz.md) | Plugin source-archive fuzz (#6) | ⚠ | A05:2021 | T1530 |
| [`headless_templates`](headless_templates.md) | Headless DOM templates (Playwright) (#14) | ⚠ | A03:2021 | T1059.007 |
| [`websocket_fuzz`](websocket_fuzz.md) | WebSocket frame fuzzer (#23) | ⚠ | A03:2021 | T1190 |
| [`login_throttle_deep`](login_throttle_deep.md) | Deep throttle mapping (opt-in, 20 min) | · | A07:2021 | T1110.003 |
| [`authenticated`](authenticated.md) | Authenticated scan | · | A01:2021 | T1078 |